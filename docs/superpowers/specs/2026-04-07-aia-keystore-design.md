# AIA-til-KeyStore: Automatisk sertifikatresolving

**Dato:** 2026-04-07
**Status:** Godkjent

## Formål

Når et TLS-handshake feiler fordi serveren sender en ufullstendig sertifikatkjede, skal Sancus automatisk hente manglende sertifikater via AIA (Authority Information Access) og sende en komplett kjede til den underliggende TrustManager. Dette gjelder både agent-modus og CLI-modus, med forskjellig mekanikk.

## Done-kriterier

- Agent: `SancusAgentTrustManager` utvider kjeden via AIA før delegering til original TrustManager
- Agent: Resolvede kjeder caches med TTL for å unngå gjentatte nettverkskall
- Agent: Fail-open — hvis AIA-resolving feiler, sendes original kjede videre uendret
- Agent: Aktivert by default, konfigurerbart via `sancus.aia.resolve`
- CLI: `sancus resolve --keystore <path>` skriver en JKS-fil med alle resolvede sertifikater
- Tester for alle nye komponenter

## Out of scope

- Persistent caching av AIA-resolvede sertifikater på disk (kun in-memory)
- Mutasjon av JVM-ens globale TrustStore (cacerts)
- Client-sertifikat-resolving (kun server-kjeder)
- Konfigurerbar KeyStore-type i CLI (kun JKS for MVP)

## Verifiseringskommandoer

```bash
mvn -pl sancus-core,sancus-agent,sancus-cli test
mvn -pl sancus-agent verify  # integrasjonstester
```

---

## Arkitektur

### Tilnærming: Dobbel callback (audit + resolve)

Utvider det eksisterende bootstrap-bridge-mønsteret med en ny callback. Bootstrap-shimen (`SancusAgentTrustManager`) kan ikke referere sancus-core-klasser, så AIA-logikken lever i agent classloader og eksponeres som en `Function<X509Certificate[], X509Certificate[]>`.

### Dataflyt (agent-modus)

```
SSLContext.init() intercepted av SslContextAdvice
  → TrustManager[] wrappet i SancusAgentTrustManager

checkServerTrusted(chain, authType):
  1. tryResolve(chain) → extendedChain
     - Kall resolveCallback.apply(chain)
     - Fail-open: exception → returner original chain
     - Null callback → returner original chain
  2. delegate.checkServerTrusted(extendedChain, authType)
  3. fireAudit(chain, rejected)  // NB: original chain, ikke extendedChain
```

---

## Komponentdesign

### 1. SancusAgentTrustManager (bootstrap classloader)

**Endringer:**

Nytt statisk felt:
```java
public static volatile Function<X509Certificate[], X509Certificate[]> resolveCallback = null;
```

Ny privat metode:
```java
private X509Certificate[] tryResolve(X509Certificate[] chain) {
    try {
        Function<X509Certificate[], X509Certificate[]> cb = resolveCallback;
        if (cb != null) {
            return cb.apply(chain);
        }
    } catch (Exception ignored) {
        // Resolve must never affect SSL handshake outcome
    }
    return chain;
}
```

Alle tre `checkServerTrusted()`-overloads endres til å kalle `tryResolve(chain)` først, og bruke resultatet for delegering. Audit-callbacken mottar fortsatt den **originale** kjeden fra serveren — ikke den resolvede — slik at `ChainCompletenessCheck` fortsetter å rapportere manglende intermediates.

**Unngå dobbel AIA-fetch:** Når `sancus.checks.chain=true`, vil `ChainCompletenessCheck` kalle `RemoteResolver.resolve()` på den originale (ufullstendige) kjeden — samme AIA-kall som resolve-callbacken allerede har gjort. For å unngå dette dupliserte nettverkskallet, lagrer `SancusAgentTrustManager` den resolvede kjeden i en `ThreadLocal<X509Certificate[]>` etter vellykket resolving. `AgentAuditCallback` leser denne ThreadLocal-en og gjør den tilgjengelig for `ChainCompletenessCheck` via en ny overload eller et nytt felt på `HandshakeInfo` (`resolvedChain`). `ChainCompletenessCheck` kan da sammenligne original og resolvet kjede for å rapportere manglende intermediates uten å re-fetche.

ThreadLocal ryddes i en `finally`-blokk etter `fireAudit()` for å unngå lekkasje.

### 2. AgentResolveCallback (ny klasse, agent classloader)

**Pakke:** `org.brylex.sancus.agent`
**Implementerer:** `Function<X509Certificate[], X509Certificate[]>`

**Logikk:**
1. Beregn fingerprint av leaf-sertifikat (chain[0])
2. Sjekk cache — hvis nylig resolvet, returner cachet kjede
3. Registrer BouncyCastle-provider hvis ikke allerede registrert (`Security.addProvider(new BouncyCastleProvider())` — idempotent, returnerer -1 hvis allerede registrert)
4. Bygg `CertificateChain` fra arrayet
5. Kjør `RemoteResolver.resolve()` for å hente manglende sertifikater via AIA. **NB:** `RemoteResolver` skriver `System.out.println()` under nedlasting — dette må dempes i agent-modus for å unngå å forurense applikasjonens stdout. Løsning: redirect `System.out` midlertidig til en no-op stream under kallet, eller refaktorer `RemoteResolver` til å bruke `java.util.logging` (foretrukket, ryddigere langsiktig).
6. Konverter tilbake til `X509Certificate[]` (leaf → intermediates → root)
7. Lagre i cache med TTL
8. Returner utvidet kjede

**Krav: BouncyCastle-provider.** `RemoteResolver` bruker `JcaX509CertificateConverter` med `BouncyCastleProvider.PROVIDER_NAME`. I CLI-modus registreres denne i `SancusCli` static initializer, men i agent-modus skjer dette aldri. `AgentResolveCallback` må registrere provideren ved oppstart (i konstruktør eller ved første kall). `Security.addProvider()` er idempotent — trygt å kalle flere ganger.

**Cache:** `ConcurrentHashMap<String, CachedChain>` der `CachedChain` er en record med `X509Certificate[] chain` og `Instant resolvedAt`. Samme TTL som audit-cache (`sancus.cache.ttl.minutes`, default 5 min). Eviction ved hver N-te kall, likt `AuditCache`.

**Feilhåndtering:** Alle exceptions fanges, original chain returneres (fail-open).

### 3. AgentConfig-utvidelse

Ny property:
- `sancus.aia.resolve` (default: `true`) — aktiverer/deaktiverer AIA-resolving

Nytt felt i recorden:
```java
boolean aiaResolveEnabled
```

### 4. SancusAgent.premain() — wiring

Etter eksisterende audit callback-setup:
```java
if (config.aiaResolveEnabled()) {
    AgentResolveCallback resolveCallback = new AgentResolveCallback(config);
    SancusAgentTrustManager.resolveCallback = resolveCallback;

    // Også på bootstrap-kopien (samme mønster som audit callback)
    Class<?> bootstrapCopy = Class.forName(...);
    Field resolveField = bootstrapCopy.getField("resolveCallback");
    resolveField.set(null, resolveCallback);
}
```

### 5. CLI: ResolveCommand — KeyStore-output

**Ny parameter:** `--keystore <path>` (valgfri, picocli `@Option`)

**Viktig: non-interactive path.** `ResolveCommand.call()` har i dag en interaktiv `while (true)` løkke som venter på stdin-input. Når `--keystore` er angitt, skal kommandoen kjøre non-interaktivt:

1. Kjør handshake og bygg initial kjede (som i dag)
2. **Sjekk at kjeden har minst ett sertifikat.** Hvis handshake feilet (DNS, timeout, TLS-feil) vil `CertificateChain` være tom. I så fall: print feilmelding til stderr og returner exit code 2 (CRITICAL). Ikke skriv KeyStore-fil.
3. Kjør `RemoteResolver.resolve()` automatisk for å hente manglende sertifikater via AIA
4. Samle alle sertifikater fra `CertificateChain.toList()`
5. Opprett `KeyStore.getInstance("JKS")` — JKS for kompatibilitet med eksisterende loading-kode (`Util.loadKeyStore()`, `ResolveCommand --truststore`, `CertificateChain`)
6. Legg inn hvert sertifikat med alias basert på subject CN
7. Skriv til angitt path med passord "changeit" (konvensjon fra cacerts)
8. Returner exit code 0 (suksess) — **ikke** gå inn i interaktiv løkke

Uten `--keystore`: uendret oppførsel (interaktiv løkke som i dag).

**Begrunnelse for JKS fremfor PKCS12:** Hele kodebasen bruker `KeyStore.getInstance("JKS")` — `Util.loadKeyStore()`, `CertificateChain`, `ResolveCommand --truststore`, og alle tester. En PKCS12-fil ville ikke kunne leses tilbake av noen av disse uten samtidige endringer i loaderen. JKS er riktig valg for MVP.

---

## Testplan

### Enhetstester

- **AgentResolveCallback:** Mock `RemoteResolver`, verifiser at kjeden utvides korrekt
- **AgentResolveCallback cache:** Verifiser at andre kall med samme leaf returnerer cachet resultat, og at TTL-eviction fungerer
- **SancusAgentTrustManager.tryResolve():** Null callback → original chain, exception → original chain, fungerende callback → utvidet chain
- **AgentConfig:** Verifiser parsing av `sancus.aia.resolve` property

### Integrasjonstester

- **Agent premain:** Server med ufullstendig kjede → verifiser at handshake lykkes med AIA-resolve aktiv
- **CLI:** `--keystore` flagg → verifiser at JKS-fil skrives og kan leses tilbake med `Util.loadKeyStore()`

---

## Beslutninger

| Beslutning | Valg | Begrunnelse |
|------------|------|-------------|
| Kontekst | Begge moduser (agent + CLI) | Forskjellig mekanikk, men samme underliggende resolver |
| AIA-resolvede certs | Brukes kun i wrapperen, ikke lagt i globale stores | Isolasjon, ingen sideeffekter |
| Scope | Intermediates + root | La original TrustManager avgjøre trust |
| Feilhåndtering | Fail-open | Sancus skal aldri gjøre ting verre |
| Default | Aktivert by default | Hele poenget med featuren |
| Kjede til delegat | Hele utvidede kjeden (server → root) | TrustManager bestemmer selv |
| CLI output | JKS KeyStore | Kompatibelt med eksisterende `Util.loadKeyStore()` og hele kodebasen |
| BouncyCastle i agent | Registreres av `AgentResolveCallback` | `RemoteResolver` krever BC-provider, som kun CLI registrerer i dag |
| Audit-chain | Original (ikke resolvet) chain til audit | `ChainCompletenessCheck` må se ufullstendig kjede for å rapportere |
| RemoteResolver stdout | Dempes i agent-modus | Unngå å lekke "Downloading issuer..." til appens stdout |
| CLI `--keystore` | Non-interaktiv path, bypass interaktiv løkke | `ResolveCommand.call()` blokkerer ellers på stdin |
| Dobbel AIA-fetch | ThreadLocal + `HandshakeInfo.resolvedChain` | Unngå at `ChainCompletenessCheck` re-fetcher det resolve-callback allerede har hentet |
| Cache | TTL-basert, likt AuditCache | Gjenbruk eksisterende mønster |
