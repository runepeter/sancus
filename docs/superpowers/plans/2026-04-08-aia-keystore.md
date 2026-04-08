# AIA-til-KeyStore Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Automatisk hente manglende sertifikater via AIA og sende komplett kjede til TrustManager (agent), eller skrive JKS-fil (CLI).

**Architecture:** Utvider bootstrap bridge pattern med en `Function<X509Certificate[], X509Certificate[]>` resolve callback. Agent classloader eier AIA-logikken via `AgentResolveCallback`. CLI får non-interactive `--keystore` path. `RemoteResolver` refaktoreres til JUL for å unngå stdout-lekkasje.

**Tech Stack:** Java 25, Maven, BouncyCastle LTS8, JUL

**Design spec:** `docs/superpowers/specs/2026-04-07-aia-keystore-design.md`

---

## File Structure

**Nye filer:**
- `sancus-agent/src/main/java/org/brylex/sancus/agent/AgentResolveCallback.java` — AIA resolve callback med cache
- `sancus-agent/src/test/java/org/brylex/sancus/agent/AgentResolveCallbackTest.java` — enhetstester

**Endrede filer:**
- `sancus-agent/src/main/java/org/brylex/sancus/agent/bootstrap/SancusAgentTrustManager.java` — resolveCallback felt + tryResolve() + ThreadLocal
- `sancus-agent/src/main/java/org/brylex/sancus/agent/AgentConfig.java` — `aiaResolveEnabled` felt + system property
- `sancus-agent/src/main/java/org/brylex/sancus/agent/AgentAuditCallback.java` — les ThreadLocal, sett resolvedChain på HandshakeInfo
- `sancus-agent/src/main/java/org/brylex/sancus/agent/SancusAgent.java` — wire resolve callback
- `sancus-agent/src/test/java/org/brylex/sancus/agent/AgentConfigTest.java` — test ny property
- `sancus-core/src/main/java/org/brylex/sancus/audit/HandshakeInfo.java` — nytt `resolvedChain` felt
- `sancus-core/src/main/java/org/brylex/sancus/audit/check/ChainCompletenessCheck.java` — bruk resolvedChain for å unngå dobbel AIA-fetch
- `sancus-core/src/main/java/org/brylex/sancus/resolver/RemoteResolver.java` — JUL istedenfor System.out
- `sancus-cli/src/main/java/org/brylex/sancus/cli/command/ResolveCommand.java` — `--keystore` flag + non-interactive path

---

## Task 1: Refaktorer RemoteResolver til JUL

Erstatt `System.out.println()` med `java.util.logging.Logger` slik at agent-modus ikke lekker til appens stdout. `ChainCompletenessCheck` sin stdout-redirect kan da fjernes.

**Files:**
- Modify: `sancus-core/src/main/java/org/brylex/sancus/resolver/RemoteResolver.java`
- Modify: `sancus-core/src/main/java/org/brylex/sancus/audit/check/ChainCompletenessCheck.java`
- Test: `sancus-core/src/test/java/org/brylex/sancus/resolver/RemoteResolverTest.java`

- [ ] **Step 1: Erstatt System.out med JUL i RemoteResolver**

I `RemoteResolver.java`, legg til logger-felt og erstatt alle `System.out.println()`:

```java
// Topp av klassen, etter class-deklarasjon:
private static final java.util.logging.Logger LOG = java.util.logging.Logger.getLogger("sancus");
```

I `resolve(CertificateChain chain)` linje 138, erstatt:
```java
// FRA:
System.out.println("Downloading issuer [" + issuer.dn() + "] certificate from [" + url + "]\n");
// TIL:
LOG.info("Downloading issuer [" + issuer.dn() + "] certificate from [" + url + "]");
```

I `resolve(ChainEntry entry)` linje 168, erstatt:
```java
// FRA:
System.out.println("There's no remote download location for [" + issuer.dn() + "].\n");
// TIL:
LOG.info("There's no remote download location for [" + issuer.dn() + "].");
```

I `resolve(ChainEntry entry)` linje 173, erstatt:
```java
// FRA:
System.out.println("Downloading issuer [" + entry.issuedBy().dn() + "] certificate from [" + url + "]\n");
// TIL:
LOG.info("Downloading issuer [" + entry.issuedBy().dn() + "] certificate from [" + url + "]");
```

- [ ] **Step 2: Fjern stdout-redirect i ChainCompletenessCheck**

I `ChainCompletenessCheck.java`, fjern stdout-redirect-koden rundt `RemoteResolver`-kallet (linjene 31-38):

```java
// FRA:
PrintStream originalOut = System.out;
try {
    System.setOut(new PrintStream(OutputStream.nullOutputStream()));
    new RemoteResolver().resolve(certChain);
} catch (Exception ignored) {
} finally {
    System.setOut(originalOut);
}

// TIL:
try {
    new RemoteResolver().resolve(certChain);
} catch (Exception ignored) {
}
```

Fjern også ubrukte imports `java.io.OutputStream` og `java.io.PrintStream`.

- [ ] **Step 3: Kjør tester**

Run: `mvn -pl sancus-core test -q`
Expected: Alle tester passerer. `RemoteResolverTest` og `AuditCheckTest` (som tester `ChainCompletenessCheck`) skal fortsatt fungere.

- [ ] **Step 4: Commit**

```bash
git add sancus-core/src/main/java/org/brylex/sancus/resolver/RemoteResolver.java \
       sancus-core/src/main/java/org/brylex/sancus/audit/check/ChainCompletenessCheck.java
git commit -m "refactor: replace System.out with JUL in RemoteResolver"
```

---

## Task 2: Utvid HandshakeInfo med resolvedChain

Legg til et valgfritt `resolvedChain`-felt som `ChainCompletenessCheck` kan bruke istedenfor å kalle `RemoteResolver` på nytt.

**Files:**
- Modify: `sancus-core/src/main/java/org/brylex/sancus/audit/HandshakeInfo.java`
- Modify: `sancus-core/src/main/java/org/brylex/sancus/audit/check/ChainCompletenessCheck.java`
- Test: `sancus-core/src/test/java/org/brylex/sancus/audit/check/AuditCheckTest.java`

- [ ] **Step 1: Skriv test for ChainCompletenessCheck med resolvedChain**

I `AuditCheckTest.java`, legg til en ny test i `ChainCompletenessCheckTest` nested class. Bruker `Certificates.LOCALHOST` (ufullstendig kjede) og `generateCert()` (self-signed = root) som allerede finnes i test-klassen:

```java
@Test
void usesResolvedChainWhenPresent() throws Exception {
    // Certificates.LOCALHOST is an incomplete chain (leaf issued by intermediate CA)
    X509Certificate leaf = Certificates.LOCALHOST;

    // Generate a self-signed cert to act as "root" in the resolved chain
    X509Certificate fakeRoot = generateCert(365, 2048, "SHA256WithRSA");
    X509Certificate[] resolvedChain = new X509Certificate[]{leaf, fakeRoot};

    // HandshakeInfo with resolvedChain set — should use it instead of fetching via AIA
    HandshakeInfo info = new HandshakeInfo("TLSv1.3", "TLS_AES_256_GCM_SHA384",
            new X509Certificate[]{leaf}, resolvedChain);

    List<Finding> findings = check.check(info, new X509Certificate[]{leaf});

    // Should report WARNING (chain was incomplete, resolved via AIA)
    assertFalse(findings.isEmpty());
    Finding.ChainFinding cf = (Finding.ChainFinding) findings.getFirst();
    assertEquals(Severity.WARNING, cf.severity());
    assertTrue(cf.summary().contains("resolved via AIA"));
}
```

Merk: Denne testen vil ikke kompilere ennå — `HandshakeInfo` tar ikke 4 argumenter. Det er forventet.

- [ ] **Step 2: Utvid HandshakeInfo til å ha resolvedChain**

Endre `HandshakeInfo.java` fra:

```java
public record HandshakeInfo(String protocol, String cipherSuite, X509Certificate[] serverChain) {
}
```

Til:

```java
public record HandshakeInfo(String protocol, String cipherSuite, X509Certificate[] serverChain,
                            X509Certificate[] resolvedChain) {

    /** Convenience constructor for backwards compatibility (no resolved chain). */
    public HandshakeInfo(String protocol, String cipherSuite, X509Certificate[] serverChain) {
        this(protocol, cipherSuite, serverChain, null);
    }
}
```

- [ ] **Step 3: Oppdater ChainCompletenessCheck til å bruke resolvedChain**

I `ChainCompletenessCheck.java`, erstatt hele `check()`-metoden:

```java
@Override
public List<Finding> check(HandshakeInfo handshakeInfo, X509Certificate[] chain) {
    if (chain.length == 0) {
        return List.of(new ChainFinding(Severity.CRITICAL, 0, false, List.of("no certificates")));
    }

    CertificateChain certChain = CertificateChain.create(chain);

    if (certChain.isComplete()) {
        return List.of(new ChainFinding(Severity.OK, chain.length, true, List.of()));
    }

    // If a resolved chain is available (from agent AIA resolve), use it
    // instead of fetching again via RemoteResolver
    if (handshakeInfo.resolvedChain() != null && handshakeInfo.resolvedChain().length > chain.length) {
        X509Certificate[] resolved = handshakeInfo.resolvedChain();
        X509Certificate last = resolved[resolved.length - 1];
        boolean complete = last.getSubjectX500Principal().equals(last.getIssuerX500Principal());

        if (complete) {
            int extra = resolved.length - chain.length;
            return List.of(new ChainFinding(Severity.WARNING, chain.length, false,
                    List.of(extra + " certificate(s) resolved via AIA")));
        } else {
            // Resolved chain is still incomplete — report CRITICAL
            String missingIssuer = last.getIssuerX500Principal().getName();
            return List.of(new ChainFinding(Severity.CRITICAL, chain.length, false, List.of(missingIssuer)));
        }
    }

    // No pre-resolved chain — fetch via AIA
    try {
        new RemoteResolver().resolve(certChain);
    } catch (Exception ignored) {
    }

    if (certChain.isComplete()) {
        int resolved = certChain.toList().size() - chain.length;
        return List.of(new ChainFinding(Severity.WARNING, chain.length, false,
                List.of(resolved + " certificate(s) resolved via AIA")));
    }

    X509Certificate last = chain[chain.length - 1];
    String missingIssuer = last.getIssuerX500Principal().getName();
    return List.of(new ChainFinding(Severity.CRITICAL, chain.length, false, List.of(missingIssuer)));
}
```

- [ ] **Step 4: Kjør tester**

Run: `mvn -pl sancus-core test -q`
Expected: Alle eksisterende tester passerer + ny test passerer. Eksisterende bruk av 3-arg `HandshakeInfo` fungerer via convenience-konstruktøren.

- [ ] **Step 5: Commit**

```bash
git add sancus-core/src/main/java/org/brylex/sancus/audit/HandshakeInfo.java \
       sancus-core/src/main/java/org/brylex/sancus/audit/check/ChainCompletenessCheck.java \
       sancus-core/src/test/java/org/brylex/sancus/audit/check/AuditCheckTest.java
git commit -m "feat: add resolvedChain to HandshakeInfo, skip double AIA fetch"
```

---

## Task 3: Utvid AgentConfig med aiaResolveEnabled

Legg til ny system property `sancus.aia.resolve` (default `true`).

**Files:**
- Modify: `sancus-agent/src/main/java/org/brylex/sancus/agent/AgentConfig.java`
- Modify: `sancus-agent/src/test/java/org/brylex/sancus/agent/AgentConfigTest.java`

- [ ] **Step 1: Skriv test for ny property**

I `AgentConfigTest.java`:

Oppdater `cleanup()` til å rydde ny property:
```java
@AfterEach
void cleanup() {
    AgentConfig.reset();
    System.clearProperty("sancus.enabled");
    System.clearProperty("sancus.checks.ocsp");
    System.clearProperty("sancus.checks.chain");
    System.clearProperty("sancus.log.level");
    System.clearProperty("sancus.cache.ttl.minutes");
    System.clearProperty("sancus.aia.resolve");
}
```

Legg til tester:
```java
@Test
void aiaResolveEnabledByDefault() {
    AgentConfig config = AgentConfig.fromSystemProperties();
    assertTrue(config.aiaResolveEnabled());
}

@Test
void aiaResolveCanBeDisabled() {
    System.setProperty("sancus.aia.resolve", "false");
    AgentConfig config = AgentConfig.fromSystemProperties();
    assertFalse(config.aiaResolveEnabled());
}
```

- [ ] **Step 2: Kjør test, verifiser at den feiler**

Run: `mvn -pl sancus-agent test -Dtest=AgentConfigTest -q`
Expected: Kompileringsfeil — `aiaResolveEnabled()` finnes ikke på `AgentConfig`.

- [ ] **Step 3: Legg til feltet i AgentConfig**

I `AgentConfig.java`, endre record-signaturen:

```java
public record AgentConfig(
        boolean enabled,
        boolean ocspEnabled,
        boolean chainEnabled,
        boolean aiaResolveEnabled,
        Severity logLevel,
        int cacheTtlMinutes
) {
```

Oppdater `fromSystemProperties()`:

```java
public static AgentConfig fromSystemProperties() {
    boolean enabled = Boolean.parseBoolean(System.getProperty("sancus.enabled", "true"));
    boolean ocsp = Boolean.parseBoolean(System.getProperty("sancus.checks.ocsp", "false"));
    boolean chain = Boolean.parseBoolean(System.getProperty("sancus.checks.chain", "false"));
    boolean aiaResolve = Boolean.parseBoolean(System.getProperty("sancus.aia.resolve", "true"));
    String levelName = System.getProperty("sancus.log.level", "WARNING");
    Severity logLevel = Severity.valueOf(levelName);
    int ttl = Integer.parseInt(System.getProperty("sancus.cache.ttl.minutes", "5"));
    return new AgentConfig(enabled, ocsp, chain, aiaResolve, logLevel, ttl);
}
```

- [ ] **Step 4: Kjør tester**

Run: `mvn -pl sancus-agent test -Dtest=AgentConfigTest -q`
Expected: Alle tester passerer, inkludert de to nye.

- [ ] **Step 5: Commit**

```bash
git add sancus-agent/src/main/java/org/brylex/sancus/agent/AgentConfig.java \
       sancus-agent/src/test/java/org/brylex/sancus/agent/AgentConfigTest.java
git commit -m "feat: add sancus.aia.resolve config property (default true)"
```

---

## Task 4: Legg til resolveCallback + tryResolve() + ThreadLocal i SancusAgentTrustManager

Utvid bootstrap-shimen med resolve-callback og ThreadLocal for å passere resolvet kjede til audit.

**Files:**
- Modify: `sancus-agent/src/main/java/org/brylex/sancus/agent/bootstrap/SancusAgentTrustManager.java`
- Test: `sancus-agent/src/test/java/org/brylex/sancus/agent/bootstrap/SancusAgentTrustManagerTest.java`

- [ ] **Step 1: Skriv tester for tryResolve() og ThreadLocal**

Opprett `sancus-agent/src/test/java/org/brylex/sancus/agent/bootstrap/SancusAgentTrustManagerTest.java`.

Bruker en enkel capturing delegate (ingen Mockito — ikke i agent POM) som fanger opp hvilken chain som ble delegert:

```java
package org.brylex.sancus.agent.bootstrap;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.InputStream;
import java.net.Socket;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;

class SancusAgentTrustManagerTest {

    private X509Certificate testCert;
    private X509Certificate testCert2;

    @BeforeEach
    void setUp() throws Exception {
        KeyStore ks = KeyStore.getInstance("JKS");
        try (InputStream is = getClass().getResourceAsStream("/jks/selfsigned.jks")) {
            ks.load(is, "changeit".toCharArray());
        }
        testCert = (X509Certificate) ks.getCertificate("test");
        // Use same cert as a stand-in for a second cert in the resolved chain
        testCert2 = testCert;
    }

    @AfterEach
    void cleanup() {
        SancusAgentTrustManager.resolveCallback = null;
        SancusAgentTrustManager.auditCallback = null;
        SancusAgentTrustManager.lastResolvedChain.remove();
    }

    @Test
    void delegatesResolvedChainWhenCallbackSet() throws Exception {
        X509Certificate[] original = {testCert};
        X509Certificate[] resolved = {testCert, testCert2};

        CapturingDelegate delegate = new CapturingDelegate();
        SancusAgentTrustManager.resolveCallback = chain -> resolved;

        SancusAgentTrustManager tm = new SancusAgentTrustManager(delegate);
        tm.checkServerTrusted(original, "RSA");

        // Delegate should receive the resolved chain
        assertSame(resolved, delegate.lastChain);
    }

    @Test
    void usesOriginalChainWhenCallbackNull() throws Exception {
        X509Certificate[] original = {testCert};

        CapturingDelegate delegate = new CapturingDelegate();
        SancusAgentTrustManager.resolveCallback = null;

        SancusAgentTrustManager tm = new SancusAgentTrustManager(delegate);
        tm.checkServerTrusted(original, "RSA");

        assertSame(original, delegate.lastChain);
    }

    @Test
    void failOpenWhenCallbackThrows() throws Exception {
        X509Certificate[] original = {testCert};

        CapturingDelegate delegate = new CapturingDelegate();
        SancusAgentTrustManager.resolveCallback = chain -> {
            throw new RuntimeException("AIA fetch failed");
        };

        SancusAgentTrustManager tm = new SancusAgentTrustManager(delegate);
        tm.checkServerTrusted(original, "RSA");

        // Should fall back to original chain
        assertSame(original, delegate.lastChain);
    }

    @Test
    void auditsWithOriginalChain() throws Exception {
        X509Certificate[] original = {testCert};
        X509Certificate[] resolved = {testCert, testCert2};

        CapturingDelegate delegate = new CapturingDelegate();
        SancusAgentTrustManager.resolveCallback = chain -> resolved;

        X509Certificate[][] auditedChain = {null};
        SancusAgentTrustManager.auditCallback = (chain, rejected) -> auditedChain[0] = chain;

        SancusAgentTrustManager tm = new SancusAgentTrustManager(delegate);
        tm.checkServerTrusted(original, "RSA");

        // Audit should receive the ORIGINAL chain, not resolved
        assertSame(original, auditedChain[0]);
    }

    @Test
    void setsThreadLocalWithResolvedChain() throws Exception {
        X509Certificate[] original = {testCert};
        X509Certificate[] resolved = {testCert, testCert2};

        CapturingDelegate delegate = new CapturingDelegate();
        SancusAgentTrustManager.resolveCallback = chain -> resolved;

        X509Certificate[][] capturedThreadLocal = {null};
        SancusAgentTrustManager.auditCallback = (chain, rejected) -> {
            capturedThreadLocal[0] = SancusAgentTrustManager.lastResolvedChain.get();
        };

        SancusAgentTrustManager tm = new SancusAgentTrustManager(delegate);
        tm.checkServerTrusted(original, "RSA");

        // ThreadLocal should have been set during audit
        assertSame(resolved, capturedThreadLocal[0]);
        // ThreadLocal should be cleared after the call
        assertNull(SancusAgentTrustManager.lastResolvedChain.get());
    }

    /**
     * Minimal X509ExtendedTrustManager that captures the chain passed to checkServerTrusted.
     * Avoids Mockito dependency.
     */
    private static class CapturingDelegate extends X509ExtendedTrustManager {
        X509Certificate[] lastChain;

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
            this.lastChain = chain;
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) {
            this.lastChain = chain;
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {
            this.lastChain = chain;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) {}

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {}

        @Override
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }
}
```

- [ ] **Step 2: Kjør test, verifiser at den feiler**

Run: `mvn -pl sancus-agent test -Dtest=SancusAgentTrustManagerTest -q`
Expected: Kompileringsfeil — `resolveCallback`, `lastResolvedChain` finnes ikke.

- [ ] **Step 3: Implementer endringene i SancusAgentTrustManager**

Erstatt hele filen `SancusAgentTrustManager.java`:

```java
package org.brylex.sancus.agent.bootstrap;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.function.BiConsumer;
import java.util.function.Function;

/**
 * Bootstrap shim — lives in the bootstrap classloader. NO references to sancus-core allowed.
 * Only JDK types + the callbacks that are injected by premain().
 */
public class SancusAgentTrustManager extends X509ExtendedTrustManager {

    /** Set by premain() from agent classloader. Volatile for visibility across threads. */
    public static volatile BiConsumer<X509Certificate[], Boolean> auditCallback = null;

    /** Set by premain() from agent classloader. Resolves incomplete chains via AIA. */
    public static volatile Function<X509Certificate[], X509Certificate[]> resolveCallback = null;

    /** Carries the resolved chain to the audit callback within the same thread. */
    public static final ThreadLocal<X509Certificate[]> lastResolvedChain = new ThreadLocal<>();

    private final X509ExtendedTrustManager extendedDelegate;
    private final X509TrustManager simpleDelegate;
    private final boolean delegateIsExtended;

    public SancusAgentTrustManager(X509ExtendedTrustManager delegate) {
        this.extendedDelegate = delegate;
        this.simpleDelegate = delegate;
        this.delegateIsExtended = true;
    }

    public SancusAgentTrustManager(X509TrustManager delegate) {
        this.extendedDelegate = null;
        this.simpleDelegate = delegate;
        this.delegateIsExtended = false;
    }

    // ---- checkServerTrusted (3 overloads) ----

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        X509Certificate[] resolved = tryResolve(chain);
        CertificateException thrown = null;
        try {
            simpleDelegate.checkServerTrusted(resolved, authType);
        } catch (CertificateException e) {
            thrown = e;
        } finally {
            try {
                lastResolvedChain.set(resolved);
                fireAudit(chain, thrown != null);
            } finally {
                lastResolvedChain.remove();
            }
        }
        if (thrown != null) throw thrown;
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        X509Certificate[] resolved = tryResolve(chain);
        CertificateException thrown = null;
        try {
            if (delegateIsExtended) {
                extendedDelegate.checkServerTrusted(resolved, authType, socket);
            } else {
                simpleDelegate.checkServerTrusted(resolved, authType);
            }
        } catch (CertificateException e) {
            thrown = e;
        } finally {
            try {
                lastResolvedChain.set(resolved);
                fireAudit(chain, thrown != null);
            } finally {
                lastResolvedChain.remove();
            }
        }
        if (thrown != null) throw thrown;
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        X509Certificate[] resolved = tryResolve(chain);
        CertificateException thrown = null;
        try {
            if (delegateIsExtended) {
                extendedDelegate.checkServerTrusted(resolved, authType, engine);
            } else {
                simpleDelegate.checkServerTrusted(resolved, authType);
            }
        } catch (CertificateException e) {
            thrown = e;
        } finally {
            try {
                lastResolvedChain.set(resolved);
                fireAudit(chain, thrown != null);
            } finally {
                lastResolvedChain.remove();
            }
        }
        if (thrown != null) throw thrown;
    }

    // ---- checkClientTrusted (3 overloads) — pure delegation ----

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        simpleDelegate.checkClientTrusted(chain, authType);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        if (delegateIsExtended) {
            extendedDelegate.checkClientTrusted(chain, authType, socket);
        } else {
            simpleDelegate.checkClientTrusted(chain, authType);
        }
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        if (delegateIsExtended) {
            extendedDelegate.checkClientTrusted(chain, authType, engine);
        } else {
            simpleDelegate.checkClientTrusted(chain, authType);
        }
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return simpleDelegate.getAcceptedIssuers();
    }

    // ---- Internal ----

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

    private void fireAudit(X509Certificate[] chain, boolean rejected) {
        try {
            BiConsumer<X509Certificate[], Boolean> cb = auditCallback;
            if (cb != null) {
                cb.accept(chain, rejected);
            }
        } catch (Exception ignored) {
            // Callback must never affect SSL handshake outcome
        }
    }
}
```

- [ ] **Step 4: Kjør tester**

Run: `mvn -pl sancus-agent test -Dtest=SancusAgentTrustManagerTest -q`
Expected: Alle 5 tester passerer.

- [ ] **Step 5: Kjør alle agent-tester**

Run: `mvn -pl sancus-agent test -q`
Expected: Alle tester passerer (inkludert eksisterende `SancusAgentIT`).

- [ ] **Step 6: Commit**

```bash
git add sancus-agent/src/main/java/org/brylex/sancus/agent/bootstrap/SancusAgentTrustManager.java \
       sancus-agent/src/test/java/org/brylex/sancus/agent/bootstrap/SancusAgentTrustManagerTest.java
git commit -m "feat: add resolveCallback, tryResolve, and ThreadLocal to SancusAgentTrustManager"
```

---

## Task 5: Implementer AgentResolveCallback

Ny klasse som bruker `RemoteResolver` til å utvide ufullstendige kjeder, med cache og BouncyCastle-registrering.

**Files:**
- Create: `sancus-agent/src/main/java/org/brylex/sancus/agent/AgentResolveCallback.java`
- Create: `sancus-agent/src/test/java/org/brylex/sancus/agent/AgentResolveCallbackTest.java`

- [ ] **Step 1: Skriv tester**

Opprett `sancus-agent/src/test/java/org/brylex/sancus/agent/AgentResolveCallbackTest.java`:

```java
package org.brylex.sancus.agent;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;

class AgentResolveCallbackTest {

    @BeforeEach
    void setUp() {
        Security.addProvider(new BouncyCastleProvider());
        AgentConfig.reset();
    }

    @AfterEach
    void cleanup() {
        AgentConfig.reset();
    }

    @Test
    void returnsOriginalChainWhenAlreadyComplete() throws Exception {
        // A self-signed cert is already "complete"
        X509Certificate selfSigned = loadCertFromJks("/jks/selfsigned.jks", "test");
        X509Certificate[] chain = {selfSigned};

        AgentResolveCallback callback = new AgentResolveCallback();
        X509Certificate[] result = callback.apply(chain);

        // Self-signed chain is already complete, should return as-is
        assertEquals(chain.length, result.length);
    }

    @Test
    void cachesResolvedChainByLeafFingerprint() throws Exception {
        X509Certificate selfSigned = loadCertFromJks("/jks/selfsigned.jks", "test");
        X509Certificate[] chain = {selfSigned};

        AgentResolveCallback callback = new AgentResolveCallback();
        X509Certificate[] first = callback.apply(chain);
        X509Certificate[] second = callback.apply(chain);

        // Both calls should return equivalent results (cached)
        assertEquals(first.length, second.length);
    }

    @Test
    void returnsOriginalChainOnError() {
        // Null cert should trigger an error inside the callback
        X509Certificate[] chain = {null};

        AgentResolveCallback callback = new AgentResolveCallback();
        X509Certificate[] result = callback.apply(chain);

        // Should fail-open and return original chain
        assertSame(chain, result);
    }

    private X509Certificate loadCertFromJks(String resource, String alias) throws Exception {
        KeyStore ks = KeyStore.getInstance("JKS");
        try (InputStream is = getClass().getResourceAsStream(resource)) {
            ks.load(is, "changeit".toCharArray());
        }
        return (X509Certificate) ks.getCertificate(alias);
    }
}
```

- [ ] **Step 2: Kjør test, verifiser at den feiler**

Run: `mvn -pl sancus-agent test -Dtest=AgentResolveCallbackTest -q`
Expected: Kompileringsfeil — `AgentResolveCallback` finnes ikke.

- [ ] **Step 3: Implementer AgentResolveCallback**

Opprett `sancus-agent/src/main/java/org/brylex/sancus/agent/AgentResolveCallback.java`:

```java
package org.brylex.sancus.agent;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.brylex.sancus.CertificateChain;
import org.brylex.sancus.resolver.RemoteResolver;

import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;
import java.util.logging.Logger;

public class AgentResolveCallback implements Function<X509Certificate[], X509Certificate[]> {

    private static final Logger LOG = Logger.getLogger("sancus");

    private record CachedChain(X509Certificate[] chain, Instant resolvedAt) {}

    private final ConcurrentHashMap<String, CachedChain> cache = new ConcurrentHashMap<>();
    private final AtomicLong callCount = new AtomicLong(0);

    public AgentResolveCallback() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Override
    public X509Certificate[] apply(X509Certificate[] chain) {
        try {
            if (chain == null || chain.length == 0) return chain;

            String fingerprint = AuditCache.fingerprint(chain[0]);

            // Check cache
            CachedChain cached = cache.get(fingerprint);
            int ttlMinutes = AgentConfig.current().cacheTtlMinutes();
            if (cached != null && Instant.now().isBefore(cached.resolvedAt().plusSeconds(ttlMinutes * 60L))) {
                return cached.chain();
            }

            // Evict stale entries periodically
            long count = callCount.incrementAndGet();
            if (count % 100 == 0) {
                Instant cutoff = Instant.now().minusSeconds(ttlMinutes * 60L);
                cache.entrySet().removeIf(e -> e.getValue().resolvedAt().isBefore(cutoff));
            }

            // Build CertificateChain and resolve via AIA
            CertificateChain certChain = CertificateChain.create(chain);

            if (certChain.isComplete()) {
                cache.put(fingerprint, new CachedChain(chain, Instant.now()));
                return chain;
            }

            new RemoteResolver().resolve(certChain);

            X509Certificate[] resolved = certChain.toList().toArray(new X509Certificate[0]);
            cache.put(fingerprint, new CachedChain(resolved, Instant.now()));

            if (resolved.length > chain.length) {
                LOG.info("[sancus] AIA resolved " + (resolved.length - chain.length) + " additional certificate(s)");
            }

            return resolved;
        } catch (Exception e) {
            // Fail-open: return original chain
            LOG.fine("[sancus] AIA resolve failed, using original chain: " + e.getMessage());
            return chain;
        }
    }

    /** Visible for testing. */
    void clearCache() {
        cache.clear();
        callCount.set(0);
    }
}
```

- [ ] **Step 4: Kjør tester**

Run: `mvn -pl sancus-agent test -Dtest=AgentResolveCallbackTest -q`
Expected: Alle 3 tester passerer.

- [ ] **Step 5: Commit**

```bash
git add sancus-agent/src/main/java/org/brylex/sancus/agent/AgentResolveCallback.java \
       sancus-agent/src/test/java/org/brylex/sancus/agent/AgentResolveCallbackTest.java
git commit -m "feat: add AgentResolveCallback with AIA resolution and TTL cache"
```

---

## Task 6: Oppdater AgentAuditCallback til å lese ThreadLocal

`AgentAuditCallback` leser `SancusAgentTrustManager.lastResolvedChain` og sender den videre til `HandshakeInfo`.

**Files:**
- Modify: `sancus-agent/src/main/java/org/brylex/sancus/agent/AgentAuditCallback.java`

- [ ] **Step 1: Oppdater AgentAuditCallback**

I `AgentAuditCallback.java`, endre `accept()`-metoden til å lese ThreadLocal og sette resolvedChain på HandshakeInfo:

```java
package org.brylex.sancus.agent;

import org.brylex.sancus.agent.bootstrap.SancusAgentTrustManager;
import org.brylex.sancus.audit.AuditCheck;
import org.brylex.sancus.audit.Finding;
import org.brylex.sancus.audit.HandshakeInfo;
import org.brylex.sancus.audit.Severity;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.logging.Level;
import java.util.logging.Logger;

public class AgentAuditCallback implements BiConsumer<X509Certificate[], Boolean> {

    private static final Logger LOG = Logger.getLogger("sancus");

    @Override
    public void accept(X509Certificate[] chain, Boolean rejected) {
        if (chain == null || chain.length == 0) return;

        // Dedup: use fingerprint of leaf certificate
        X509Certificate leaf = chain[0];
        String fingerprint = AuditCache.fingerprint(leaf);
        if (AuditCache.INSTANCE.recentlyAudited(fingerprint)) {
            return; // already audited within TTL
        }

        AgentConfig config = AgentConfig.current();
        if (!config.enabled()) return;

        String prefix = Boolean.TRUE.equals(rejected) ? "[REJECTED] " : "";
        List<AuditCheck> checks = config.checks();
        Severity minLevel = config.logLevel();

        // Read resolved chain from ThreadLocal on the bootstrap-loaded copy.
        // The agent-loader import and the bootstrap-loaded class are different classes
        // with separate static fields, so we must use reflection to read the bootstrap copy.
        X509Certificate[] resolvedChain = readResolvedChainFromBootstrap();

        HandshakeInfo handshakeInfo = new HandshakeInfo("unknown", "unknown", chain, resolvedChain);

        for (AuditCheck check : checks) {
            try {
                List<Finding> findings = check.check(handshakeInfo, chain);
                for (Finding finding : findings) {
                    if (finding.severity().compareTo(minLevel) >= 0) {
                        Level julLevel = toJulLevel(finding.severity());
                        String message = "[sancus] " + finding.severity() + " \u2014 " + prefix + finding.summary();
                        LOG.log(julLevel, message);
                    }
                }
            } catch (Exception ignored) {
                // A failing check must not propagate — keep auditing remaining checks
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static X509Certificate[] readResolvedChainFromBootstrap() {
        try {
            Class<?> bootstrapCopy = Class.forName(
                    "org.brylex.sancus.agent.bootstrap.SancusAgentTrustManager", true, null);
            java.lang.reflect.Field field = bootstrapCopy.getField("lastResolvedChain");
            ThreadLocal<X509Certificate[]> tl = (ThreadLocal<X509Certificate[]>) field.get(null);
            return tl != null ? tl.get() : null;
        } catch (Exception e) {
            // Fallback: try agent-loader copy (unit test scenario)
            return SancusAgentTrustManager.lastResolvedChain.get();
        }
    }

    private static Level toJulLevel(Severity severity) {
        return switch (severity) {
            case OK -> Level.INFO;
            case WARNING, CRITICAL -> Level.WARNING;
        };
    }
}
```

- [ ] **Step 2: Kjør alle agent-tester**

Run: `mvn -pl sancus-agent test -q`
Expected: Alle tester passerer.

- [ ] **Step 3: Commit**

```bash
git add sancus-agent/src/main/java/org/brylex/sancus/agent/AgentAuditCallback.java
git commit -m "feat: read ThreadLocal resolvedChain in AgentAuditCallback"
```

---

## Task 7: Wire resolve callback i SancusAgent.premain()

Koble `AgentResolveCallback` inn i premain, på både agent- og bootstrap classloader.

**Files:**
- Modify: `sancus-agent/src/main/java/org/brylex/sancus/agent/SancusAgent.java`

- [ ] **Step 1: Oppdater premain()**

I `SancusAgent.java`, legg til resolve callback-wiring etter audit callback-setup (etter linje 51):

```java
// Wire AIA resolve callback (if enabled)
if (config.aiaResolveEnabled()) {
    AgentResolveCallback resolveCallback = new AgentResolveCallback();
    SancusAgentTrustManager.resolveCallback = resolveCallback;

    // Also set on the bootstrap-loaded copy
    try {
        Class<?> bootstrapCopy = Class.forName(
                "org.brylex.sancus.agent.bootstrap.SancusAgentTrustManager", true, null);
        if (bootstrapCopy != SancusAgentTrustManager.class) {
            java.lang.reflect.Field resolveField = bootstrapCopy.getField("resolveCallback");
            resolveField.set(null, resolveCallback);
        }
    } catch (ClassNotFoundException e) {
        logger.warning("[sancus] Bootstrap copy not found — AIA resolve will not work: " + e.getMessage());
    }

    logger.info("[sancus] AIA resolve enabled");
}
```

- [ ] **Step 2: Kjør integrasjonstester**

Run: `mvn -pl sancus-agent verify -q`
Expected: Alle tester passerer, inkludert `SancusAgentIT`.

- [ ] **Step 3: Commit**

```bash
git add sancus-agent/src/main/java/org/brylex/sancus/agent/SancusAgent.java
git commit -m "feat: wire AgentResolveCallback in premain with bootstrap bridge"
```

---

## Task 8: CLI --keystore flag i ResolveCommand

Legg til non-interaktiv path når `--keystore` er angitt.

**Files:**
- Modify: `sancus-cli/src/main/java/org/brylex/sancus/cli/command/ResolveCommand.java`
- Test: `sancus-cli/src/test/java/org/brylex/sancus/cli/command/ResolveCommandKeystoreTest.java`

- [ ] **Step 1: Legg til --keystore option og non-interactive path**

I `ResolveCommand.java`, legg til nytt felt etter eksisterende options:

```java
@Option(names = {"--keystore"}, description = "Write resolved chain to JKS keystore (non-interactive)")
Path keystorePath;
```

Endre `call()` metoden:

```java
@Override
public Integer call() {
    CertificateChain chain = resolveCertificateChain();

    // Non-interactive keystore export
    if (keystorePath != null) {
        return exportKeystore(chain);
    }

    // Interactive mode (existing behavior)
    String command;
    while (true) {
        command = ConsoleUtil.consoleInput("Operation");

        if ("q".equalsIgnoreCase(command)) {
            return 1;
        }
        if ("r".equalsIgnoreCase(command)) {
            resolveCommandHandler(chain);
        }
        if ("h".equalsIgnoreCase(command)) {
            handshakeCommandHandler(chain);
        }
        if ("s".equalsIgnoreCase(command)) {
            saveCommandHandler(chain);
        }
    }
}

private Integer exportKeystore(CertificateChain chain) {
    // Check that handshake produced a chain
    List<X509Certificate> certs = chain.toList();
    if (certs.isEmpty()) {
        System.err.println("Error: No certificates received from handshake. Cannot write keystore.");
        return 2;
    }

    // Resolve via AIA
    try {
        new RemoteResolver().resolve(chain);
    } catch (Exception e) {
        System.err.println("Warning: AIA resolution failed: " + e.getMessage());
    }

    // Collect all resolved certs
    List<X509Certificate> resolvedCerts = chain.toList();

    try {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null);

        for (X509Certificate cert : resolvedCerts) {
            String cn = cert.getSubjectX500Principal().getName();
            String alias = cn.length() > 64 ? cn.substring(0, 64) : cn;
            // Ensure unique alias
            int i = 1;
            String uniqueAlias = alias;
            while (ks.containsAlias(uniqueAlias)) {
                uniqueAlias = alias + "_" + i++;
            }
            ks.setCertificateEntry(uniqueAlias, cert);
        }

        try (OutputStream os = Files.newOutputStream(keystorePath, StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING)) {
            ks.store(os, "changeit".toCharArray());
        }

        System.out.println("Wrote " + resolvedCerts.size() + " certificate(s) to [" + keystorePath.toAbsolutePath() + "].");
        return 0;
    } catch (Exception e) {
        System.err.println("Error: Failed to write keystore: " + e.getMessage());
        return 2;
    }
}
```

Legg til nødvendige imports øverst:

```java
import java.security.cert.X509Certificate;
import java.util.List;
```

- [ ] **Step 2: Kjør CLI-tester**

Run: `mvn -pl sancus-cli test -q`
Expected: Alle eksisterende tester passerer (ingen endring i interaktiv modus).

- [ ] **Step 3: Commit**

```bash
git add sancus-cli/src/main/java/org/brylex/sancus/cli/command/ResolveCommand.java
git commit -m "feat: add --keystore flag for non-interactive JKS export"
```

---

## Task 9: Full verifisering

Kjør alle tester på tvers av moduler.

**Files:** Ingen endringer.

- [ ] **Step 1: Kjør alle enhetstester**

Run: `mvn -pl sancus-core,sancus-agent,sancus-cli test -q`
Expected: Alle tester passerer.

- [ ] **Step 2: Kjør integrasjonstester**

Run: `mvn -pl sancus-agent verify -q`
Expected: Alle integrasjonstester passerer.

- [ ] **Step 3: Full build**

Run: `mvn clean verify -q`
Expected: BUILD SUCCESS.
