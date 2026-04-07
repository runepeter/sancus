# Sancus Java Agent — Design Spec

**Dato:** 2026-04-07
**Status:** Draft (rev 2 — adresserer review-funn)

## Oversikt

Gjør Sancus til en Java Agent (`-javaagent`) som intercepter utgående TLS-handshakes i sanntid og kjører audit-checks mot sertifikatkjeder — inkludert handshakes som feiler. Utviklere fester agenten til en hvilken som helst JVM-applikasjon uten kodeendringer.

## Done-kriterier

- [ ] `java -javaagent:sancus-agent.jar -jar myapp.jar` intercepter TLS-tilkoblinger
- [ ] Handshakes via `null` TrustManager[] (JVM-defaults) fanges også
- [ ] Avviste handshakes (CertificateException) audites og logges
- [ ] Billige checks (Expiry, WeakAlgorithm, Transparency) kjører automatisk
- [ ] Dyre checks (OCSP, ChainCompleteness) er opt-in via system properties
- [ ] Findings logges via JUL med severity-filtrering
- [ ] Deduplisering basert på cert-fingerprint — maks én gang per TTL-intervall
- [ ] Integrasjonstest bekrefter end-to-end-flyten via premain
- [ ] Agent-JAR inneholder kun nødvendige dependencies (ingen Logback/picocli/jansi)

## Out of scope

- SSLSocket/SSLEngine-instrumentering (protocol/cipher-info)
- ProtocolCheck i agent-modus
- JSON-fil output
- JMX MBeans
- SPI/plugin-system for custom handlers
- Produksjon/ops-hardening (metrics, alerting, webhooks)
- Konfigurasjonsfiler (kun system properties i MVP)

## Verifiseringskommandoer

```bash
# Bygg hele prosjektet
mvn clean package

# Kjør tester
mvn test

# Verifiser agent-JAR manifest
unzip -p sancus-agent/target/sancus-agent-develop-SNAPSHOT.jar META-INF/MANIFEST.MF | grep Premain-Class

# Verifiser at agent-JAR IKKE inneholder Logback/picocli
jar tf sancus-agent/target/sancus-agent-develop-SNAPSHOT.jar | grep -E "(logback|picocli|jansi)" && echo "FAIL: uønskede deps" || echo "OK"

# Verifiser at CLI-JAR fortsatt fungerer
java -jar sancus-cli/target/sancus-cli-develop-SNAPSHOT.jar audit --host example.com
```

---

## 1. Modul-struktur

Splittes i tre Maven-moduler for å isolere agent-runtimen fra CLI-dependencies:

```
sancus/
├── pom.xml                         ← parent
├── sancus-core/                    ← audit-motor, ingen logging-framework
│   └── src/main/java/org/brylex/sancus/
│       ├── audit/                  ← AuditCheck, Finding, Severity, checks/
│       ├── resolver/               ← HandshakeResolver, RemoteResolver, etc.
│       ├── CertificateChain.java
│       ├── SancusTrustManager.java
│       └── ...
├── sancus-agent/                   ← javaagent JAR (core + byte-buddy, JUL)
│   └── src/main/java/org/brylex/sancus/agent/
│       ├── SancusAgent.java
│       ├── SancusAgentTrustManager.java
│       ├── SslContextAdvice.java
│       ├── AgentConfig.java
│       └── AuditCache.java
└── sancus-cli/                     ← CLI JAR (core + picocli + logback + jansi + gson)
    └── src/main/java/org/brylex/sancus/cli/
        ├── SancusCli.java
        └── command/
```

**Begrunnelse (funn #7):** Én felles JAR drar inn Logback, picocli, Jansi og Gson i agenten, som risikerer klassekonflikter med mål-applikasjonen. Ved å splitte moduler får agenten kun `sancus-core` + Byte Buddy + BouncyCastle — ingen logging-framework, ingen CLI-deps.

**Dependencies per modul:**
- `sancus-core`: BouncyCastle (bcprov, bcpkix), SLF4J API (kun interface, ingen implementasjon)
- `sancus-agent`: sancus-core, Byte Buddy
- `sancus-cli`: sancus-core, picocli, Logback, Jansi, Gson

## 2. Instrumentering

### premain()

```
premain(String args, Instrumentation inst)
  ├─ AgentConfig.fromSystemProperties()
  ├─ if (!config.enabled()) return
  ├─ Bootstrap-injeksjon: legg agent-klasser på bootstrap classloader
  └─ AgentBuilder.Default()
       .with(RedefinitionStrategy.RETRANSFORMATION)
       .enableBootstrapInjection(inst, tempDir)
       .type(is(SSLContext.class))
       .transform(...)
       .installOn(inst)
```

**Bootstrap-injeksjon (funn #4):** `SSLContext` lastes av bootstrap classloader. Advice-koden og `SancusAgentTrustManager` må også være på bootstrap classloader, ellers får vi `ClassNotFoundException` når transformert JDK-kode prøver å referere agent-klasser. Byte Buddy's `enableBootstrapInjection(inst, tempDir)` løser dette ved å injisere en temp-JAR med agent-klassene på bootstrap classpath.

`tempDir` opprettes via `Files.createTempDirectory("sancus-agent")` med shutdown-hook for opprydding.

### SslContextAdvice

Byte Buddy `@Advice.OnMethodEnter` på `SSLContext.init(KeyManager[], TrustManager[], SecureRandom)`:

**Null-håndtering (funn #1):** Når `TrustManager[]` er `null`, bruker JVM default TrustManagerFactory. Advice-koden må håndtere dette:

```java
@Advice.OnMethodEnter
static void onInit(@Advice.Argument(value = 1, readOnly = false) TrustManager[] tms) {
    // Når null: resolvér JVM-defaults eksplisitt
    if (tms == null) {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm());
        tmf.init((KeyStore) null);  // trigger default truststore
        tms = tmf.getTrustManagers();
    }

    // Wrap hver X509TrustManager/X509ExtendedTrustManager
    TrustManager[] wrapped = new TrustManager[tms.length];
    for (int i = 0; i < tms.length; i++) {
        if (tms[i] instanceof SancusAgentTrustManager) {
            wrapped[i] = tms[i];  // unngå dobbel-wrapping
        } else if (tms[i] instanceof X509ExtendedTrustManager ext) {
            wrapped[i] = new SancusAgentTrustManager(ext);
        } else if (tms[i] instanceof X509TrustManager x509) {
            wrapped[i] = new SancusAgentTrustManager(x509);
        } else {
            wrapped[i] = tms[i];  // ikke-X509, behold som den er
        }
    }
    tms = wrapped;
}
```

### SancusAgentTrustManager

**Typebevaring (funn #2):** Extender `X509ExtendedTrustManager`, ikke bare `X509TrustManager`. Dette bevarer JSSE-kontekst (Socket/SSLEngine-overloads) og unngår at JSSE faller tilbake til mindre informerte kodepaths.

**Audit-alltid via try/finally (funn #3):** Audit kjører uansett om delegaten kaster. Avviste handshakes er spesielt interessante.

```java
public class SancusAgentTrustManager extends X509ExtendedTrustManager {
    private final X509ExtendedTrustManager delegate;
    // Hvis original bare er X509TrustManager, wraps i en adapter

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        CertificateException thrown = null;
        try {
            delegate.checkServerTrusted(chain, authType);
        } catch (CertificateException e) {
            thrown = e;
        } finally {
            auditChain(chain, thrown != null);
        }
        if (thrown != null) throw thrown;
    }

    // Samme mønster for Extended-overloads:
    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException { /* same try/finally → auditChain(chain, rejected) */ }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException { /* same try/finally → auditChain(chain, rejected) */ }

    private void auditChain(X509Certificate[] chain, boolean rejected) {
        String cacheKey = AuditCache.fingerprint(chain[0]);
        if (AuditCache.INSTANCE.recentlyAudited(cacheKey)) return;

        HandshakeInfo info = new HandshakeInfo(null, null, chain);
        AgentConfig config = AgentConfig.current();
        List<Finding> findings = config.checks().stream()
            .flatMap(c -> c.check(info, chain).stream())
            .toList();

        String prefix = rejected ? "[REJECTED] " : "";
        findings.stream()
            .filter(f -> f.severity().compareTo(config.minLogLevel()) >= 0)
            .forEach(f -> logger.log(toJulLevel(f.severity()),
                "[sancus] {0} — {1}{2}", new Object[]{f.severity(), prefix, f.summary()}));
    }

    // Delegering for øvrige metoder
    @Override
    public void checkClientTrusted(X509Certificate[] c, String a) throws CertificateException {
        delegate.checkClientTrusted(c, a);
    }
    @Override
    public void checkClientTrusted(X509Certificate[] c, String a, Socket s) throws CertificateException {
        delegate.checkClientTrusted(c, a, s);
    }
    @Override
    public void checkClientTrusted(X509Certificate[] c, String a, SSLEngine e) throws CertificateException {
        delegate.checkClientTrusted(c, a, e);
    }
    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return delegate.getAcceptedIssuers();
    }
}
```

**X509TrustManager → X509ExtendedTrustManager-adapter:** Når den originale TrustManager bare implementerer `X509TrustManager` (ikke Extended), wraps den i en tynn adapter som delegerer de tre basis-metodene og kaster `UnsupportedOperationException` for Socket/SSLEngine-overloads (som aldri vil kalles i denne kode-pathen, siden JSSE velger overload basert på den registrerte typen).

## 3. Deduplisering

**Global, fingerprint-basert cache (funn #5):**

```java
public final class AuditCache {
    public static final AuditCache INSTANCE = new AuditCache();

    private final ConcurrentHashMap<String, Instant> cache = new ConcurrentHashMap<>();

    public static String fingerprint(X509Certificate cert) {
        // SHA-256 over DER-encoded cert — unik per sertifikat
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(cert.getEncoded());
        return HexFormat.of().formatHex(digest);
    }

    public boolean recentlyAudited(String fingerprint) {
        Instant lastSeen = cache.get(fingerprint);
        if (lastSeen != null && lastSeen.plus(AgentConfig.current().cacheTtl()).isAfter(Instant.now())) {
            return true;
        }
        cache.put(fingerprint, Instant.now());
        return false;
    }

    // Enkel eviction: fjern entries eldre enn 2x TTL ved hver 100. kall
    // Unngår ubegrenset vekst uten å trenge en scheduled executor
}
```

- **Singleton** — deles på tvers av alle `SancusAgentTrustManager`-instanser
- **Fingerprint** som nøkkel — SHA-256 av DER-encoded cert. Unikt per sertifikat, ingen falske treff ved SAN-overlapp eller cert-rotasjon
- **Thread-safe** via `ConcurrentHashMap`

## 4. Konfigurasjon

Utelukkende via system properties. Ingen konfigurasjonsfiler i MVP.

| Property | Default | Beskrivelse |
|---|---|---|
| `sancus.enabled` | `true` | Master kill-switch |
| `sancus.checks.ocsp` | `false` | Opt-in: OCSP-sjekk (nettverkskall) |
| `sancus.checks.chain` | `false` | Opt-in: Chain completeness (AIA-oppslag) |
| `sancus.log.level` | `WARNING` | Minimum severity: `OK`, `WARNING`, `CRITICAL` |
| `sancus.cache.ttl.minutes` | `5` | Deduplisering: TTL per cert |

```java
public record AgentConfig(
    boolean enabled,
    boolean ocspEnabled,
    boolean chainEnabled,
    Severity minLogLevel,
    Duration cacheTtl
) {
    private static volatile AgentConfig instance;

    public static AgentConfig current() {
        if (instance == null) instance = fromSystemProperties();
        return instance;
    }

    public List<AuditCheck> checks() {
        List<AuditCheck> checks = new ArrayList<>(List.of(
            new ExpiryCheck(), new WeakAlgorithmCheck(), new TransparencyCheck()
        ));
        if (ocspEnabled) checks.add(new OcspCheck());
        if (chainEnabled) checks.add(new ChainCompletenessCheck());
        return checks;
    }

    public static AgentConfig fromSystemProperties() { ... }
}
```

**Billige checks (alltid på):** ExpiryCheck, WeakAlgorithmCheck, TransparencyCheck.

**ProtocolCheck** er deaktivert i agent-modus (krever socket-info som TrustManager ikke har tilgang til via Extended-overloads med Socket/SSLEngine — men dette er en mulig fremtidig utvidelse).

## 5. Logging og observerbarhet

### JUL, ikke SLF4J

Agent-koden bruker `java.util.logging`. CLI-koden bruker Logback. Audit-koden i `sancus-core` forblir logging-fri (returnerer `Finding`-objekter).

Med modulsplitt (seksjon 1) er dette nå konsistent: agent-JARen inneholder ikke Logback.

### Log-format

```
WARNING [sancus] CRITICAL — Certificate expired: CN=api.example.com (expired 2026-03-01T00:00:00Z)
WARNING [sancus] WARNING — SHA256withRSA with 2048-bit key for CN=api.example.com
WARNING [sancus] CRITICAL — [REJECTED] Certificate expired: CN=api.example.com (expired 2026-03-01T00:00:00Z)
INFO    [sancus] OK — 3 SCT(s) embedded in CN=api.example.com
```

Findings fra avviste handshakes prefixes med `[REJECTED]` for å skille dem fra vellykkede.

## 6. Bygging og manifest

### Agent-modul pom.xml

```xml
<dependencies>
    <dependency>
        <groupId>org.brylex</groupId>
        <artifactId>sancus-core</artifactId>
        <version>${project.version}</version>
    </dependency>
    <dependency>
        <groupId>net.bytebuddy</groupId>
        <artifactId>byte-buddy</artifactId>
        <version>1.17.5</version>
    </dependency>

    <!-- Test -->
    <dependency>
        <groupId>org.junit.jupiter</groupId>
        <artifactId>junit-jupiter</artifactId>
        <scope>test</scope>
    </dependency>
    <dependency>
        <groupId>net.bytebuddy</groupId>
        <artifactId>byte-buddy-agent</artifactId>
        <version>1.17.5</version>
        <scope>test</scope>
    </dependency>
</dependencies>

<build>
    <plugins>
        <plugin>
            <groupId>org.apache.maven.plugins</groupId>
            <artifactId>maven-shade-plugin</artifactId>
            <configuration>
                <transformers>
                    <transformer implementation="...ManifestResourceTransformer">
                        <manifestEntries>
                            <Premain-Class>org.brylex.sancus.agent.SancusAgent</Premain-Class>
                            <Can-Retransform-Classes>true</Can-Retransform-Classes>
                        </manifestEntries>
                    </transformer>
                    <transformer implementation="...ServicesResourceTransformer"/>
                </transformers>
            </configuration>
        </plugin>
    </plugins>
</build>
```

### CLI-modul

Beholder eksisterende shade-oppsett med `Main-Class: org.brylex.sancus.cli.SancusCli`.

### Bruksmønster

```bash
# CLI (fra sancus-cli)
java -jar sancus-cli.jar audit --host example.com

# Java Agent (fra sancus-agent)
java -javaagent:sancus-agent.jar -jar myapp.jar

# Med konfigurasjon
java -javaagent:sancus-agent.jar -Dsancus.checks.ocsp=true -Dsancus.log.level=OK -jar myapp.jar
```

## 7. Testing

### Integrasjonstest (funn #6)

Testen må verifisere faktisk premain-oppstart, ikke bare runtime attach:

1. **Maven Failsafe** for integrasjonstester (IT-suffix)
2. Start en lokal HTTPS-server med self-signed cert og en TrustManager som stoler på det
3. Konfigurér `maven-failsafe-plugin` med `-javaagent:${project.build.directory}/sancus-agent.jar` som JVM-argument — tester faktisk premain-flow
4. Gjør HTTPS-tilkobling via `HttpClient` med en `SSLContext` som stoler på test-certet
5. Verifiser findings via custom JUL handler registrert i test-setup
6. Separat test: gjør tilkobling med en `SSLContext` som **ikke** stoler på certet, verifiser at `[REJECTED]`-findings logges og `CertificateException` propageres

### Unit-tester

- `AgentConfig.fromSystemProperties()` med ulike property-kombinasjoner
- `AuditCache` — fingerprint-generering, TTL-basert deduplisering, eviction
- `SancusAgentTrustManager` — verifiser at audit kjører via try/finally ved CertificateException
- `SslContextAdvice` — null TrustManager[] resolverer defaults, dobbel-wrapping forhindres, X509ExtendedTrustManager bevares

### Test-dependencies

```xml
<dependency>
    <groupId>net.bytebuddy</groupId>
    <artifactId>byte-buddy-agent</artifactId>
    <version>1.17.5</version>
    <scope>test</scope>
</dependency>
```

## 8. Fremtidige utvidelser (utenfor MVP)

- SSLSocket-instrumentering for ProtocolCheck (og Socket/SSLEngine-kontekst i Extended-overloads)
- JSON-fil output og JMX MBeans
- SPI for custom Finding-handlers
- `sancus.policy=BLOCK` for å avvise svake tilkoblinger
- Ops-hardening: metrics, alerting, webhooks
- Separat lightweight agent-JAR uten BouncyCastle (kun ExpiryCheck + WeakAlgorithmCheck)
