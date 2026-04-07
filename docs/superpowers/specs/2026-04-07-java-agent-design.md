# Sancus Java Agent — Design Spec

**Dato:** 2026-04-07
**Status:** Draft (rev 3 — bootstrap bridge, adapter-fix, null-semantikk)

## Oversikt

Gjør Sancus til en Java Agent (`-javaagent`) som intercepter utgående TLS-handshakes i sanntid og kjører audit-checks mot sertifikatkjeder — inkludert handshakes som feiler. Utviklere fester agenten til en hvilken som helst JVM-applikasjon uten kodeendringer.

## Done-kriterier

- [ ] `java -javaagent:sancus-agent.jar -jar myapp.jar` intercepter TLS-tilkoblinger
- [ ] Handshakes med eksplisitt `TrustManager[]` fanges og audites
- [ ] Avviste handshakes (CertificateException) audites og logges med `[REJECTED]`-prefix
- [ ] Billige checks (Expiry, WeakAlgorithm, Transparency) kjører automatisk
- [ ] Dyre checks (OCSP, ChainCompleteness) er opt-in via system properties
- [ ] Findings logges via JUL med severity-filtrering
- [ ] Deduplisering basert på cert-fingerprint — maks én gang per TTL-intervall
- [ ] Integrasjonstest bekrefter end-to-end-flyten via premain (Failsafe)
- [ ] Agent-JAR inneholder kun nødvendige dependencies (ingen Logback/picocli/jansi)

## Kjente begrensninger (MVP)

- **`SSLContext.init(km, null, sr)` fanges ikke.** Når `TrustManager[]` er `null`, bruker JVM providerens interne defaults. Å materialisere egne defaults i advice ville endre semantikken til `init()`, noe som bryter prinsippet "observer uten å endre". De fleste produksjons-HTTP-klienter (HttpClient, OkHttp, Apache HC) bruker eksplisitte TrustManagers. Dekkes eventuelt i fremtidig iterasjon via `TrustManagerFactory.getTrustManagers()`-instrumentering.
- **ProtocolCheck er deaktivert.** Krever socket/engine-kontekst som TrustManager-wrapping ikke gir. Dekkes ved SSLSocket/SSLEngine-instrumentering i fremtidig iterasjon.

## Out of scope

- SSLSocket/SSLEngine-instrumentering (protocol/cipher-info)
- ProtocolCheck i agent-modus
- JSON-fil output, JMX MBeans
- SPI/plugin-system for custom handlers
- Produksjon/ops-hardening (metrics, alerting, webhooks)
- Konfigurasjonsfiler (kun system properties i MVP)
- Fange `SSLContext.init()` med null TrustManager[]

## Verifiseringskommandoer

```bash
# Bygg hele prosjektet
mvn clean package

# Kjør unit-tester + integrasjonstester (Failsafe)
mvn verify

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
├── sancus-agent/                   ← javaagent JAR
│   └── src/main/java/org/brylex/sancus/agent/
│       ├── SancusAgent.java        ← premain(), agent classloader
│       ├── AgentConfig.java        ← agent classloader
│       ├── AgentAuditCallback.java ← audit-logikk, agent classloader
│       ├── AuditCache.java         ← agent classloader
│       └── bootstrap/
│           └── SancusAgentTrustManager.java  ← bootstrap classloader (minimal)
└── sancus-cli/                     ← CLI JAR (core + picocli + logback + jansi + gson)
    └── src/main/java/org/brylex/sancus/cli/
        ├── SancusCli.java
        └── command/
```

**Dependencies per modul:**
- `sancus-core`: BouncyCastle (bcprov, bcpkix)
- `sancus-agent`: sancus-core, Byte Buddy
- `sancus-cli`: sancus-core, picocli, Logback, Jansi, Gson

## 2. Bootstrap bridge-arkitektur

### Problemet

`SSLContext` lastes av bootstrap classloader. Advice som transformerer `SSLContext.init()` kjører i bootstrap-kontekst. Alle klasser som advice-koden refererer må derfor også være tilgjengelige fra bootstrap.

Å injisere hele `sancus-core` (med BouncyCastle, audit-checks, etc.) på bootstrap classloader er risikabelt og unødvendig stort. I stedet brukes et **bridge-mønster**.

### Løsningen: Minimal bootstrap shim + callback

**To lag:**

1. **Bootstrap-lag** (`SancusAgentTrustManager`): En tynn wrapper som kun delegerer TrustManager-kall og kaller en `BiConsumer<X509Certificate[], Boolean>` callback. Ingen referanser til sancus-core, AgentConfig, AuditCache, eller noen annen agent-klasse. Kun JDK-typer.

2. **Agent-lag** (`AgentAuditCallback`, `AgentConfig`, `AuditCache`): Tung audit-logikk som kjører i agent classloader. Settes som callback av `premain()`.

```
Bootstrap classloader:
  └─ SancusAgentTrustManager (kun JDK-typer: X509ExtendedTrustManager, BiConsumer)

Agent classloader:
  ├─ SancusAgent (premain)
  ├─ SslContextAdvice (inlines i SSLContext via Byte Buddy)
  ├─ AgentAuditCallback (BiConsumer-impl, refererer sancus-core)
  ├─ AgentConfig
  └─ AuditCache
```

### premain()

```java
public class SancusAgent {
    public static void premain(String args, Instrumentation inst) throws Exception {
        AgentConfig config = AgentConfig.fromSystemProperties();
        if (!config.enabled()) return;

        // 1. Sett opp audit-callback (agent classloader)
        AgentAuditCallback callback = new AgentAuditCallback(config);
        SancusAgentTrustManager.setAuditCallback(callback);

        // 2. Bootstrap-injiser kun SancusAgentTrustManager
        Path tempDir = Files.createTempDirectory("sancus-agent");
        Runtime.getRuntime().addShutdownHook(new Thread(() -> deleteRecursive(tempDir)));

        // 3. Installer instrumentering
        new AgentBuilder.Default()
            .with(RedefinitionStrategy.RETRANSFORMATION)
            .enableBootstrapInjection(inst, tempDir.toFile())
            .type(named("javax.net.ssl.SSLContext"))
            .transform((builder, type, classLoader, module, domain) ->
                builder.visit(Advice.to(SslContextAdvice.class)
                    .on(named("init"))))
            .installOn(inst);
    }
}
```

### SslContextAdvice

Byte Buddy advice som inlines i `SSLContext.init()`. Refererer kun `SancusAgentTrustManager` (bootstrap-lastet) og JDK-typer.

```java
public class SslContextAdvice {
    @Advice.OnMethodEnter
    static void onInit(@Advice.Argument(value = 1, readOnly = false) TrustManager[] tms) {
        if (tms == null) return;  // ikke observer null-defaults (kjent begrensning)

        TrustManager[] wrapped = new TrustManager[tms.length];
        for (int i = 0; i < tms.length; i++) {
            if (tms[i] instanceof SancusAgentTrustManager) {
                wrapped[i] = tms[i];  // unngå dobbel-wrapping
            } else if (tms[i] instanceof X509ExtendedTrustManager ext) {
                wrapped[i] = new SancusAgentTrustManager(ext);
            } else if (tms[i] instanceof X509TrustManager x509) {
                wrapped[i] = new SancusAgentTrustManager(x509);
            } else {
                wrapped[i] = tms[i];
            }
        }
        tms = wrapped;
    }
}
```

### SancusAgentTrustManager (bootstrap)

Minimal wrapper — **ingen referanser til sancus-core**. Kun JDK-typer.

Håndterer både `X509ExtendedTrustManager`- og `X509TrustManager`-delegater korrekt:

```java
package org.brylex.sancus.agent.bootstrap;

public class SancusAgentTrustManager extends X509ExtendedTrustManager {

    private final X509TrustManager delegate;
    private final boolean delegateIsExtended;

    // Callback settes av premain() — lever i agent classloader
    private static volatile BiConsumer<X509Certificate[], Boolean> auditCallback;

    public static void setAuditCallback(BiConsumer<X509Certificate[], Boolean> cb) {
        auditCallback = cb;
    }

    public SancusAgentTrustManager(X509ExtendedTrustManager delegate) {
        this.delegate = delegate;
        this.delegateIsExtended = true;
    }

    public SancusAgentTrustManager(X509TrustManager delegate) {
        this.delegate = delegate;
        this.delegateIsExtended = false;
    }

    // --- checkServerTrusted: 2-arg (basis) ---

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        CertificateException thrown = null;
        try {
            delegate.checkServerTrusted(chain, authType);
        } catch (CertificateException e) {
            thrown = e;
        } finally {
            fireAudit(chain, thrown != null);
        }
        if (thrown != null) throw thrown;
    }

    // --- checkServerTrusted: Socket-overload (Extended) ---

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException {
        CertificateException thrown = null;
        try {
            if (delegateIsExtended) {
                ((X509ExtendedTrustManager) delegate).checkServerTrusted(chain, authType, socket);
            } else {
                // Fallback: delegate er bare X509TrustManager, bruk 2-arg
                delegate.checkServerTrusted(chain, authType);
            }
        } catch (CertificateException e) {
            thrown = e;
        } finally {
            fireAudit(chain, thrown != null);
        }
        if (thrown != null) throw thrown;
    }

    // --- checkServerTrusted: SSLEngine-overload (Extended) ---

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException {
        CertificateException thrown = null;
        try {
            if (delegateIsExtended) {
                ((X509ExtendedTrustManager) delegate).checkServerTrusted(chain, authType, engine);
            } else {
                delegate.checkServerTrusted(chain, authType);
            }
        } catch (CertificateException e) {
            thrown = e;
        } finally {
            fireAudit(chain, thrown != null);
        }
        if (thrown != null) throw thrown;
    }

    // --- checkClientTrusted ---

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        delegate.checkClientTrusted(chain, authType);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException {
        if (delegateIsExtended) {
            ((X509ExtendedTrustManager) delegate).checkClientTrusted(chain, authType, socket);
        } else {
            delegate.checkClientTrusted(chain, authType);
        }
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException {
        if (delegateIsExtended) {
            ((X509ExtendedTrustManager) delegate).checkClientTrusted(chain, authType, engine);
        } else {
            delegate.checkClientTrusted(chain, authType);
        }
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return delegate.getAcceptedIssuers();
    }

    // --- Audit bridge ---

    private void fireAudit(X509Certificate[] chain, boolean rejected) {
        BiConsumer<X509Certificate[], Boolean> cb = auditCallback;
        if (cb != null) {
            try {
                cb.accept(chain, rejected);
            } catch (Exception ignored) {
                // Audit skal aldri påvirke applikasjonens TLS-oppførsel
            }
        }
    }
}
```

### AgentAuditCallback (agent classloader)

All tung logikk lever her — trygt i agent classloader med full tilgang til sancus-core:

```java
public class AgentAuditCallback implements BiConsumer<X509Certificate[], Boolean> {
    private static final Logger logger = Logger.getLogger("sancus");
    private final AgentConfig config;

    @Override
    public void accept(X509Certificate[] chain, Boolean rejected) {
        String fingerprint = AuditCache.fingerprint(chain[0]);
        if (AuditCache.INSTANCE.recentlyAudited(fingerprint)) return;

        HandshakeInfo info = new HandshakeInfo(null, null, chain);
        List<Finding> findings = config.checks().stream()
            .flatMap(c -> c.check(info, chain).stream())
            .toList();

        String prefix = rejected ? "[REJECTED] " : "";
        findings.stream()
            .filter(f -> f.severity().compareTo(config.minLogLevel()) >= 0)
            .forEach(f -> logger.log(toJulLevel(f.severity()),
                "[sancus] {0} — {1}{2}", new Object[]{f.severity(), prefix, f.summary()}));
    }
}
```

## 3. Deduplisering

Global, fingerprint-basert cache. Singleton deles på tvers av alle TrustManager-instanser.

```java
public final class AuditCache {
    public static final AuditCache INSTANCE = new AuditCache();

    private final ConcurrentHashMap<String, Instant> cache = new ConcurrentHashMap<>();

    public static String fingerprint(X509Certificate cert) {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(cert.getEncoded());
        return HexFormat.of().formatHex(digest);
    }

    public boolean recentlyAudited(String fingerprint) {
        Instant lastSeen = cache.get(fingerprint);
        Duration ttl = AgentConfig.current().cacheTtl();
        if (lastSeen != null && lastSeen.plus(ttl).isAfter(Instant.now())) {
            return true;
        }
        cache.put(fingerprint, Instant.now());
        return false;
    }

    // Enkel eviction: fjern entries eldre enn 2x TTL ved hver 100. kall
}
```

- **Fingerprint** (SHA-256 av DER-encoded cert) som nøkkel — unikt per sertifikat
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

## 5. Logging og observerbarhet

### JUL, ikke SLF4J

Agent-koden bruker `java.util.logging`. Med modulsplitt inneholder agent-JARen ikke Logback.

`SancusAgentTrustManager` (bootstrap) logger ikke selv — den kaller bare `fireAudit()`. All logging skjer i `AgentAuditCallback` (agent classloader) via JUL.

### Log-format

```
WARNING [sancus] CRITICAL — Certificate expired: CN=api.example.com (expired 2026-03-01T00:00:00Z)
WARNING [sancus] WARNING — SHA256withRSA with 2048-bit key for CN=api.example.com
WARNING [sancus] CRITICAL — [REJECTED] Certificate expired: CN=api.example.com (expired 2026-03-01T00:00:00Z)
INFO    [sancus] OK — 3 SCT(s) embedded in CN=api.example.com
```

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
        <plugin>
            <groupId>org.apache.maven.plugins</groupId>
            <artifactId>maven-failsafe-plugin</artifactId>
            <configuration>
                <argLine>-javaagent:${project.build.directory}/${project.build.finalName}.jar</argLine>
            </configuration>
        </plugin>
    </plugins>
</build>
```

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

### Integrasjonstester (Maven Failsafe, IT-suffix)

Kjører via `mvn verify` med faktisk `-javaagent` JVM-argument — tester premain-flow, ikke runtime attach.

1. **SancusAgentIT** — Vellykket handshake:
   - Start lokal HTTPS-server med self-signed cert
   - Opprett `SSLContext` som stoler på test-certet (eksplisitt TrustManager[])
   - Gjør HTTPS-tilkobling
   - Verifiser at findings logges via custom JUL handler

2. **SancusAgentRejectedIT** — Avvist handshake:
   - Start lokal HTTPS-server med self-signed cert
   - Opprett `SSLContext` med default TrustManager som IKKE stoler på certet
   - Gjør HTTPS-tilkobling, forvent `SSLHandshakeException`
   - Verifiser at `[REJECTED]`-findings logges
   - Verifiser at exception propageres uendret

3. **SancusAgentDoubleWrapIT** — Dobbel-wrapping:
   - Init to SSLContext-instanser med samme TrustManager
   - Verifiser at wrapping kun skjer én gang

### Unit-tester (Maven Surefire)

- `AgentConfigTest` — system property-parsing, defaults, checks()-liste
- `AuditCacheTest` — fingerprint, TTL-deduplisering, eviction
- `SancusAgentTrustManagerTest` — try/finally ved CertificateException, delegering av Extended-overloads, fallback til 2-arg for rene X509TrustManager-delegater

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

- `TrustManagerFactory.getTrustManagers()`-instrumentering for å fange null-default-caset
- SSLSocket/SSLEngine-instrumentering for ProtocolCheck
- JSON-fil output og JMX MBeans
- SPI for custom Finding-handlers
- `sancus.policy=BLOCK` for å avvise svake tilkoblinger
- Ops-hardening: metrics, alerting, webhooks
