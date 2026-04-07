# Sancus Java Agent — Design Spec

**Dato:** 2026-04-07
**Status:** Draft

## Oversikt

Gjør `sancus-agent` til en faktisk Java Agent (`-javaagent`) som intercepter alle utgående TLS-handshakes i sanntid og kjører audit-checks mot sertifikatkjeder. Utviklere fester agenten til en hvilken som helst JVM-applikasjon uten kodeendringer.

## Done-kriterier

- [ ] `java -javaagent:sancus-agent.jar -jar myapp.jar` intercepter TLS-tilkoblinger
- [ ] Billige checks (Expiry, WeakAlgorithm, Transparency) kjører automatisk
- [ ] Dyre checks (OCSP, ChainCompleteness) er opt-in via system properties
- [ ] Findings logges via JUL med severity-filtrering
- [ ] Deduplisering — samme cert audites maks én gang per TTL-intervall
- [ ] Integrasjonstest bekrefter end-to-end-flyten
- [ ] Samme JAR fungerer som både CLI og agent

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
# Bygg
mvn clean package -f sancus-agent/pom.xml

# Kjør tester
mvn test -f sancus-agent/pom.xml

# Verifiser manifest
jar tf sancus-agent/target/sancus-agent-develop-SNAPSHOT.jar META-INF/MANIFEST.MF
unzip -p sancus-agent/target/sancus-agent-develop-SNAPSHOT.jar META-INF/MANIFEST.MF | grep Premain-Class
```

---

## 1. Modul-struktur

Beholder én modul (`sancus-agent`), ny pakke `org.brylex.sancus.agent`:

```
org.brylex.sancus/
├── agent/
│   ├── SancusAgent.java              ← premain() entry point
│   ├── SancusAgentTrustManager.java  ← wrapper som kjører audit-checks
│   ├── SslContextAdvice.java         ← Byte Buddy advice for SSLContext.init()
│   └── AgentConfig.java              ← parser system properties
├── audit/                            ← eksisterende, uendret
├── cli/                              ← eksisterende, uendret
└── ...
```

Én JAR fungerer som både CLI (`java -jar`) og agent (`-javaagent:`). Audit-koden deles mellom begge modusene.

## 2. Instrumentering

### premain()

```
premain(String args, Instrumentation inst)
  ├─ AgentConfig.fromSystemProperties()
  ├─ if (!config.enabled()) return
  └─ new AgentBuilder.Default()
       .type(is(SSLContext.class))
       .transform(method(named("init"))
           .intercept(Advice.to(SslContextAdvice.class)))
       .installOn(inst)
```

### SslContextAdvice

Byte Buddy `@Advice.OnMethodEnter` på `SSLContext.init(KeyManager[], TrustManager[], SecureRandom)`:

- Iterér over `TrustManager[]`-argumentet
- Wrap hver `X509TrustManager` med `SancusAgentTrustManager`
- Erstatt arrayet in-place via `@Advice.Argument(value = 1, readOnly = false)`

### SancusAgentTrustManager

```java
public class SancusAgentTrustManager implements X509TrustManager {
    private final X509TrustManager delegate;
    private final List<AuditCheck> checks;
    private final AgentConfig config;
    private final ConcurrentHashMap<String, Instant> auditCache = new ConcurrentHashMap<>();

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        // 1. Delegér til original — aldri endre TLS-oppførsel
        delegate.checkServerTrusted(chain, authType);

        // 2. Deduplisering: sjekk cache basert på cert CN/SAN
        String cacheKey = extractSubject(chain[0]);
        if (recentlyAudited(cacheKey)) return;

        // 3. Kjør audit-checks
        HandshakeInfo info = new HandshakeInfo(null, null, chain);
        List<Finding> findings = checks.stream()
            .flatMap(c -> c.check(info, chain).stream())
            .toList();

        // 4. Logg findings over minimum severity
        findings.stream()
            .filter(f -> f.severity().compareTo(config.minLogLevel()) >= 0)
            .forEach(f -> logger.log(toJulLevel(f.severity()),
                "[sancus] {0} — {1}", new Object[]{f.severity(), f.summary()}));
    }
}
```

**Designvalg:** Delegér til original TrustManager **før** audit. Agenten observerer — den blokkerer aldri og endrer aldri TLS-oppførsel.

## 3. Konfigurasjon

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
    public static AgentConfig fromSystemProperties() {
        return new AgentConfig(
            bool("sancus.enabled", true),
            bool("sancus.checks.ocsp", false),
            bool("sancus.checks.chain", false),
            Severity.valueOf(prop("sancus.log.level", "WARNING")),
            Duration.ofMinutes(integer("sancus.cache.ttl.minutes", 5))
        );
    }
}
```

**Billige checks (alltid på):** ExpiryCheck, WeakAlgorithmCheck, TransparencyCheck.

**ProtocolCheck** er deaktivert i agent-modus (krever socket-info som TrustManager ikke har tilgang til).

## 4. Logging og observerbarhet

### JUL, ikke SLF4J

Agent-koden bruker `java.util.logging`. Begrunnelse: agenten lastes før applikasjonen — SLF4J/Logback kan skape konflikter med applikasjonens logging-stack. JUL er alltid tilgjengelig.

CLI-koden fortsetter å bruke Logback. Audit-koden (`org.brylex.sancus.audit`) forblir logging-fri — den returnerer `Finding`-objekter.

### Log-format

```
WARNING [sancus] CRITICAL — Certificate expired: CN=api.example.com (expired 2026-03-01T00:00:00Z)
WARNING [sancus] WARNING — SHA256withRSA with 2048-bit key for CN=api.example.com
INFO    [sancus] OK — 3 SCT(s) embedded in CN=api.example.com
```

### Deduplisering

Cache basert på sertifikatets CN/SAN som nøkkel. Samme cert audites maks én gang per `sancus.cache.ttl.minutes`. Unngår log-spam ved gjentatte tilkoblinger.

TrustManager mottar ikke host/port direkte — CN/SAN er et pragmatisk alternativ. Flere hosts kan dele cert, men det er akseptabelt for dedupliseringsformål.

## 5. Bygging og manifest

### Manifest

Shade-pluginen utvides med `Premain-Class`:

```xml
<transformer implementation="...ManifestResourceTransformer">
    <mainClass>org.brylex.sancus.cli.SancusCli</mainClass>
    <manifestEntries>
        <Premain-Class>org.brylex.sancus.agent.SancusAgent</Premain-Class>
        <Can-Retransform-Classes>true</Can-Retransform-Classes>
    </manifestEntries>
</transformer>
```

### Ny dependency

```xml
<dependency>
    <groupId>net.bytebuddy</groupId>
    <artifactId>byte-buddy</artifactId>
    <version>1.17.5</version>
</dependency>
```

### Bruksmønster

```bash
# CLI (eksisterende)
java -jar sancus-agent.jar audit --host example.com

# Java Agent (nytt)
java -javaagent:sancus-agent.jar -jar myapp.jar

# Med konfigurasjon
java -javaagent:sancus-agent.jar -Dsancus.checks.ocsp=true -Dsancus.log.level=OK -jar myapp.jar
```

## 6. Testing

Integrasjonstest med Byte Buddy's testing-API:

1. Start en lokal HTTPS-server (`com.sun.net.httpserver.HttpsServer`) med self-signed cert
2. Installer agenten via `ByteBuddyAgent.install()` (runtime attach)
3. Gjør en HTTPS-tilkobling via `HttpClient`
4. Verifiser at `SancusAgentTrustManager` ble kalt
5. Verifiser at findings ble logget (custom JUL handler som samler log-records)

Unit-tester for:
- `AgentConfig.fromSystemProperties()` med ulike property-kombinasjoner
- `SancusAgentTrustManager` dedupliseringslogikk
- `SslContextAdvice` TrustManager-wrapping (at den ikke wrapper seg selv)

## 7. Fremtidige utvidelser (utenfor MVP)

- SSLSocket-instrumentering for ProtocolCheck
- JSON-fil output og JMX MBeans
- SPI for custom Finding-handlers
- `sancus.policy=BLOCK` for å avvise svake tilkoblinger
- Ops-hardening: metrics, alerting, webhooks
