# Sancus Java Agent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn Sancus into a Java Agent that intercepts outgoing TLS handshakes at runtime and audits certificate chains — including rejected handshakes.

**Architecture:** Three Maven modules (core, agent, cli). Bootstrap bridge pattern: minimal TrustManager wrapper on bootstrap classloader calls audit logic in agent classloader via `BiConsumer` callback. Byte Buddy instruments `SSLContext.init()`.

**Tech Stack:** Java 25, Maven, Byte Buddy 1.17.5, BouncyCastle LTS8, JUL (agent logging), picocli (CLI only)

**Design spec:** `docs/superpowers/specs/2026-04-07-java-agent-design.md`

---

## Task 1: Split into three Maven modules (core, agent, cli)

Move existing code from the monolithic `sancus-agent` module into `sancus-core` and `sancus-cli`. The new `sancus-agent` module starts empty (agent code added in later tasks).

**Files:**
- Create: `sancus-core/pom.xml`
- Create: `sancus-cli/pom.xml`
- Modify: `pom.xml` (parent — update `<modules>`)
- Modify: `sancus-agent/pom.xml` (strip down to agent deps only)
- Move: All `org.brylex.sancus.audit.*`, `org.brylex.sancus.resolver.*`, `org.brylex.sancus.CertificateChain`, `ChainEntry`, `ChainComparator`, `ResolverSource`, `TrustStatus`, `SancusTrustManager`, `TrustMarkerVisitor`, `org.brylex.sancus.util.*` → `sancus-core`
- Move: All `org.brylex.sancus.cli.*` → `sancus-cli`
- Move: test files, test resources → corresponding modules
- Move: `src/main/resources/logback.xml` → `sancus-cli`
- Move: `src/main/resources/dummy.jks` → `sancus-core`

- [ ] **Step 1: Create `sancus-core/pom.xml`**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">

    <modelVersion>4.0.0</modelVersion>

    <parent>
        <groupId>org.brylex</groupId>
        <artifactId>sancus</artifactId>
        <version>develop-SNAPSHOT</version>
    </parent>

    <artifactId>sancus-core</artifactId>
    <packaging>jar</packaging>

    <dependencies>
        <dependency>
            <groupId>org.bouncycastle</groupId>
            <artifactId>bcprov-lts8on</artifactId>
            <version>2.73.7</version>
        </dependency>
        <dependency>
            <groupId>org.bouncycastle</groupId>
            <artifactId>bcpkix-lts8on</artifactId>
            <version>2.73.7</version>
        </dependency>

        <!-- Test dependencies -->
        <dependency>
            <groupId>org.junit.jupiter</groupId>
            <artifactId>junit-jupiter</artifactId>
            <version>5.12.2</version>
            <scope>test</scope>
        </dependency>
    </dependencies>

</project>
```

- [ ] **Step 2: Create `sancus-cli/pom.xml`**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">

    <modelVersion>4.0.0</modelVersion>

    <parent>
        <groupId>org.brylex</groupId>
        <artifactId>sancus</artifactId>
        <version>develop-SNAPSHOT</version>
    </parent>

    <artifactId>sancus-cli</artifactId>
    <packaging>jar</packaging>

    <dependencies>
        <dependency>
            <groupId>org.brylex</groupId>
            <artifactId>sancus-core</artifactId>
            <version>${project.version}</version>
        </dependency>
        <dependency>
            <groupId>ch.qos.logback</groupId>
            <artifactId>logback-classic</artifactId>
            <version>1.5.18</version>
        </dependency>
        <dependency>
            <groupId>org.fusesource.jansi</groupId>
            <artifactId>jansi</artifactId>
            <version>2.4.1</version>
        </dependency>
        <dependency>
            <groupId>info.picocli</groupId>
            <artifactId>picocli</artifactId>
            <version>4.7.7</version>
        </dependency>
        <dependency>
            <groupId>com.google.code.gson</groupId>
            <artifactId>gson</artifactId>
            <version>2.12.1</version>
        </dependency>

        <!-- Test dependencies -->
        <dependency>
            <groupId>org.junit.jupiter</groupId>
            <artifactId>junit-jupiter</artifactId>
            <version>5.12.2</version>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-surefire-plugin</artifactId>
                <version>3.5.3</version>
            </plugin>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-shade-plugin</artifactId>
                <version>3.6.0</version>
                <executions>
                    <execution>
                        <phase>package</phase>
                        <goals>
                            <goal>shade</goal>
                        </goals>
                        <configuration>
                            <transformers>
                                <transformer implementation="org.apache.maven.plugins.shade.resource.ManifestResourceTransformer">
                                    <mainClass>org.brylex.sancus.cli.SancusCli</mainClass>
                                </transformer>
                                <transformer implementation="org.apache.maven.plugins.shade.resource.ServicesResourceTransformer"/>
                            </transformers>
                            <filters>
                                <filter>
                                    <artifact>*:*</artifact>
                                    <excludes>
                                        <exclude>META-INF/*.SF</exclude>
                                        <exclude>META-INF/*.DSA</exclude>
                                        <exclude>META-INF/*.RSA</exclude>
                                    </excludes>
                                </filter>
                            </filters>
                        </configuration>
                    </execution>
                </executions>
            </plugin>
        </plugins>
    </build>

</project>
```

- [ ] **Step 3: Move core source files to `sancus-core`**

```bash
# Create directory structure
mkdir -p sancus-core/src/main/java/org/brylex/sancus/{audit/{check,output},resolver,util}
mkdir -p sancus-core/src/main/resources
mkdir -p sancus-core/src/test/java/org/brylex/sancus/{audit/{check,output},resolver,util}
mkdir -p sancus-core/src/test/resources/{jks,ca/intermediate/certs,ca/intermediate/private,ca/intermediate/csr,ca/certs,ca/private,pem}

# Move core domain classes
mv sancus-agent/src/main/java/org/brylex/sancus/CertificateChain.java sancus-core/src/main/java/org/brylex/sancus/
mv sancus-agent/src/main/java/org/brylex/sancus/ChainComparator.java sancus-core/src/main/java/org/brylex/sancus/
mv sancus-agent/src/main/java/org/brylex/sancus/ChainEntry.java sancus-core/src/main/java/org/brylex/sancus/
mv sancus-agent/src/main/java/org/brylex/sancus/ResolverSource.java sancus-core/src/main/java/org/brylex/sancus/
mv sancus-agent/src/main/java/org/brylex/sancus/TrustStatus.java sancus-core/src/main/java/org/brylex/sancus/
mv sancus-agent/src/main/java/org/brylex/sancus/SancusTrustManager.java sancus-core/src/main/java/org/brylex/sancus/
mv sancus-agent/src/main/java/org/brylex/sancus/TrustMarkerVisitor.java sancus-core/src/main/java/org/brylex/sancus/

# Move audit package
mv sancus-agent/src/main/java/org/brylex/sancus/audit/* sancus-core/src/main/java/org/brylex/sancus/audit/

# Move resolver package
mv sancus-agent/src/main/java/org/brylex/sancus/resolver/* sancus-core/src/main/java/org/brylex/sancus/resolver/

# Move util package
mv sancus-agent/src/main/java/org/brylex/sancus/util/* sancus-core/src/main/java/org/brylex/sancus/util/

# Move main resources
mv sancus-agent/src/main/resources/dummy.jks sancus-core/src/main/resources/

# Move test files for core
mv sancus-agent/src/test/java/org/brylex/sancus/CertificateChainTest.java sancus-core/src/test/java/org/brylex/sancus/
mv sancus-agent/src/test/java/org/brylex/sancus/CertificateAbsorbingVisitor.java sancus-core/src/test/java/org/brylex/sancus/
mv sancus-agent/src/test/java/org/brylex/sancus/audit/* sancus-core/src/test/java/org/brylex/sancus/audit/
mv sancus-agent/src/test/java/org/brylex/sancus/resolver/* sancus-core/src/test/java/org/brylex/sancus/resolver/
mv sancus-agent/src/test/java/org/brylex/sancus/util/Certificates.java sancus-core/src/test/java/org/brylex/sancus/util/
mv sancus-agent/src/test/java/org/brylex/sancus/util/TestServer.java sancus-core/src/test/java/org/brylex/sancus/util/

# Move all test resources (certs, keystores, CA infrastructure)
cp -r sancus-agent/src/test/resources/* sancus-core/src/test/resources/
```

- [ ] **Step 4: Move CLI source files to `sancus-cli`**

```bash
mkdir -p sancus-cli/src/main/java/org/brylex/sancus/cli/command
mkdir -p sancus-cli/src/main/resources
mkdir -p sancus-cli/src/test/java/org/brylex/sancus/cli/command

# Move CLI classes
mv sancus-agent/src/main/java/org/brylex/sancus/cli/SancusCli.java sancus-cli/src/main/java/org/brylex/sancus/cli/
mv sancus-agent/src/main/java/org/brylex/sancus/cli/command/* sancus-cli/src/main/java/org/brylex/sancus/cli/command/

# Move logback.xml to CLI
mv sancus-agent/src/main/resources/logback.xml sancus-cli/src/main/resources/

# Move CLI tests
mv sancus-agent/src/test/java/org/brylex/sancus/cli/command/SaveCommandHandlerTest.java sancus-cli/src/test/java/org/brylex/sancus/cli/command/
```

- [ ] **Step 5: Strip down `sancus-agent/pom.xml` for agent-only deps**

Replace the entire `sancus-agent/pom.xml` content with:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">

    <modelVersion>4.0.0</modelVersion>

    <parent>
        <groupId>org.brylex</groupId>
        <artifactId>sancus</artifactId>
        <version>develop-SNAPSHOT</version>
    </parent>

    <artifactId>sancus-agent</artifactId>
    <packaging>jar</packaging>

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

        <!-- Test dependencies -->
        <dependency>
            <groupId>org.junit.jupiter</groupId>
            <artifactId>junit-jupiter</artifactId>
            <version>5.12.2</version>
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
                <artifactId>maven-surefire-plugin</artifactId>
                <version>3.5.3</version>
            </plugin>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-shade-plugin</artifactId>
                <version>3.6.0</version>
                <executions>
                    <execution>
                        <phase>package</phase>
                        <goals>
                            <goal>shade</goal>
                        </goals>
                        <configuration>
                            <transformers>
                                <transformer implementation="org.apache.maven.plugins.shade.resource.ManifestResourceTransformer">
                                    <manifestEntries>
                                        <Premain-Class>org.brylex.sancus.agent.SancusAgent</Premain-Class>
                                        <Can-Retransform-Classes>true</Can-Retransform-Classes>
                                    </manifestEntries>
                                </transformer>
                                <transformer implementation="org.apache.maven.plugins.shade.resource.ServicesResourceTransformer"/>
                            </transformers>
                            <filters>
                                <filter>
                                    <artifact>*:*</artifact>
                                    <excludes>
                                        <exclude>META-INF/*.SF</exclude>
                                        <exclude>META-INF/*.DSA</exclude>
                                        <exclude>META-INF/*.RSA</exclude>
                                    </excludes>
                                </filter>
                            </filters>
                        </configuration>
                    </execution>
                </executions>
            </plugin>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-failsafe-plugin</artifactId>
                <version>3.5.3</version>
                <configuration>
                    <argLine>-javaagent:${project.build.directory}/${project.build.finalName}.jar</argLine>
                </configuration>
                <executions>
                    <execution>
                        <goals>
                            <goal>integration-test</goal>
                            <goal>verify</goal>
                        </goals>
                    </execution>
                </executions>
            </plugin>
        </plugins>
    </build>

</project>
```

- [ ] **Step 6: Update parent `pom.xml` modules**

Replace `<modules>` in `pom.xml`:

```xml
    <modules>
        <module>sancus-core</module>
        <module>sancus-agent</module>
        <module>sancus-cli</module>
    </modules>
```

- [ ] **Step 7: Clean up old sancus-agent source directories**

Remove the now-empty source directories from `sancus-agent` (all code has been moved to core/cli). Keep the `sancus-agent/src/main/java/org/brylex/sancus/agent/` directory structure for new agent code. Remove old test resources from sancus-agent (they were copied to sancus-core).

```bash
# Remove moved source directories from sancus-agent
rm -rf sancus-agent/src/main/java/org/brylex/sancus/audit
rm -rf sancus-agent/src/main/java/org/brylex/sancus/resolver
rm -rf sancus-agent/src/main/java/org/brylex/sancus/util
rm -rf sancus-agent/src/main/java/org/brylex/sancus/cli
rm -f sancus-agent/src/main/java/org/brylex/sancus/CertificateChain.java
rm -f sancus-agent/src/main/java/org/brylex/sancus/ChainComparator.java
rm -f sancus-agent/src/main/java/org/brylex/sancus/ChainEntry.java
rm -f sancus-agent/src/main/java/org/brylex/sancus/ResolverSource.java
rm -f sancus-agent/src/main/java/org/brylex/sancus/TrustStatus.java
rm -f sancus-agent/src/main/java/org/brylex/sancus/SancusTrustManager.java
rm -f sancus-agent/src/main/java/org/brylex/sancus/TrustMarkerVisitor.java
rm -rf sancus-agent/src/test
rm -rf sancus-agent/src/main/resources

# Create agent source directory
mkdir -p sancus-agent/src/main/java/org/brylex/sancus/agent/bootstrap
mkdir -p sancus-agent/src/test/java/org/brylex/sancus/agent
```

- [ ] **Step 8: Build and verify module split**

Run: `mvn clean compile`

Expected: BUILD SUCCESS — all three modules compile.

If `Util.java` causes compile errors in `sancus-core` due to Jansi import (`org.fusesource.jansi.Ansi`), the `printChain()` and `consoleInput()` methods use Jansi which belongs in CLI. Solution: extract `printChain()` and `consoleInput()` into a new `org.brylex.sancus.cli.ConsoleUtil` class in `sancus-cli`, and remove Jansi references from `Util.java` in `sancus-core`. Keep only `loadKeyStore()` and `getEffectiveDefaultJksPath()` in `Util.java`.

- [ ] **Step 9: Run tests**

Run: `mvn test`

Expected: All existing tests pass in `sancus-core`. CLI tests pass in `sancus-cli` (if `SaveCommandHandlerTest` needs core test utilities like `Certificates.java`, add `sancus-core` as test-jar dependency or duplicate the needed helper).

- [ ] **Step 10: Commit**

```bash
git add -A
git commit -m "refactor: split into three Maven modules (core, agent, cli)"
```

---

## Task 2: AgentConfig — configuration via system properties

**Files:**
- Create: `sancus-agent/src/main/java/org/brylex/sancus/agent/AgentConfig.java`
- Create: `sancus-agent/src/test/java/org/brylex/sancus/agent/AgentConfigTest.java`

- [ ] **Step 1: Write the failing test**

```java
package org.brylex.sancus.agent;

import org.brylex.sancus.audit.Severity;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class AgentConfigTest {

    @AfterEach
    void clearProperties() {
        System.clearProperty("sancus.enabled");
        System.clearProperty("sancus.checks.ocsp");
        System.clearProperty("sancus.checks.chain");
        System.clearProperty("sancus.log.level");
        System.clearProperty("sancus.cache.ttl.minutes");
        AgentConfig.reset();
    }

    @Test
    void defaultValues() {
        AgentConfig config = AgentConfig.fromSystemProperties();
        assertTrue(config.enabled());
        assertFalse(config.ocspEnabled());
        assertFalse(config.chainEnabled());
        assertEquals(Severity.WARNING, config.minLogLevel());
        assertEquals(Duration.ofMinutes(5), config.cacheTtl());
    }

    @Test
    void customValues() {
        System.setProperty("sancus.enabled", "false");
        System.setProperty("sancus.checks.ocsp", "true");
        System.setProperty("sancus.checks.chain", "true");
        System.setProperty("sancus.log.level", "OK");
        System.setProperty("sancus.cache.ttl.minutes", "10");

        AgentConfig config = AgentConfig.fromSystemProperties();
        assertFalse(config.enabled());
        assertTrue(config.ocspEnabled());
        assertTrue(config.chainEnabled());
        assertEquals(Severity.OK, config.minLogLevel());
        assertEquals(Duration.ofMinutes(10), config.cacheTtl());
    }

    @Test
    void checksReturnsOnlyDefaultChecksWhenOptInsDisabled() {
        AgentConfig config = AgentConfig.fromSystemProperties();
        // ExpiryCheck, WeakAlgorithmCheck, TransparencyCheck
        assertEquals(3, config.checks().size());
    }

    @Test
    void checksIncludesOptInChecksWhenEnabled() {
        System.setProperty("sancus.checks.ocsp", "true");
        System.setProperty("sancus.checks.chain", "true");
        AgentConfig config = AgentConfig.fromSystemProperties();
        assertEquals(5, config.checks().size());
    }

    @Test
    void currentReturnsSameInstance() {
        AgentConfig a = AgentConfig.current();
        AgentConfig b = AgentConfig.current();
        assertSame(a, b);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn test -pl sancus-agent -Dtest=AgentConfigTest`

Expected: FAIL — `AgentConfig` class does not exist.

- [ ] **Step 3: Write implementation**

```java
package org.brylex.sancus.agent;

import org.brylex.sancus.audit.AuditCheck;
import org.brylex.sancus.audit.Severity;
import org.brylex.sancus.audit.check.ChainCompletenessCheck;
import org.brylex.sancus.audit.check.ExpiryCheck;
import org.brylex.sancus.audit.check.OcspCheck;
import org.brylex.sancus.audit.check.TransparencyCheck;
import org.brylex.sancus.audit.check.WeakAlgorithmCheck;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

public record AgentConfig(
        boolean enabled,
        boolean ocspEnabled,
        boolean chainEnabled,
        Severity minLogLevel,
        Duration cacheTtl
) {
    private static volatile AgentConfig instance;

    public static AgentConfig current() {
        if (instance == null) {
            instance = fromSystemProperties();
        }
        return instance;
    }

    public static void reset() {
        instance = null;
    }

    public List<AuditCheck> checks() {
        List<AuditCheck> checks = new ArrayList<>(List.of(
                new ExpiryCheck(),
                new WeakAlgorithmCheck(),
                new TransparencyCheck()
        ));
        if (ocspEnabled) checks.add(new OcspCheck());
        if (chainEnabled) checks.add(new ChainCompletenessCheck());
        return checks;
    }

    public static AgentConfig fromSystemProperties() {
        return new AgentConfig(
                boolProp("sancus.enabled", true),
                boolProp("sancus.checks.ocsp", false),
                boolProp("sancus.checks.chain", false),
                Severity.valueOf(System.getProperty("sancus.log.level", "WARNING")),
                Duration.ofMinutes(intProp("sancus.cache.ttl.minutes", 5))
        );
    }

    private static boolean boolProp(String key, boolean defaultValue) {
        String val = System.getProperty(key);
        return val != null ? Boolean.parseBoolean(val) : defaultValue;
    }

    private static int intProp(String key, int defaultValue) {
        String val = System.getProperty(key);
        return val != null ? Integer.parseInt(val) : defaultValue;
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `mvn test -pl sancus-agent -Dtest=AgentConfigTest`

Expected: PASS — all 5 tests green.

- [ ] **Step 5: Commit**

```bash
git add sancus-agent/src/main/java/org/brylex/sancus/agent/AgentConfig.java \
       sancus-agent/src/test/java/org/brylex/sancus/agent/AgentConfigTest.java
git commit -m "feat: add AgentConfig with system property parsing"
```

---

## Task 3: AuditCache — fingerprint-based deduplication

**Files:**
- Create: `sancus-agent/src/main/java/org/brylex/sancus/agent/AuditCache.java`
- Create: `sancus-agent/src/test/java/org/brylex/sancus/agent/AuditCacheTest.java`

- [ ] **Step 1: Write the failing test**

```java
package org.brylex.sancus.agent;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;

class AuditCacheTest {

    private AuditCache cache;

    @BeforeEach
    void setUp() {
        cache = new AuditCache();
    }

    @Test
    void fingerprintProducesHexString() throws Exception {
        // Use a self-signed cert from test resources
        X509Certificate cert = loadTestCert();
        String fp = AuditCache.fingerprint(cert);
        assertNotNull(fp);
        assertTrue(fp.matches("[0-9a-f]{64}"), "SHA-256 hex should be 64 chars: " + fp);
    }

    @Test
    void fingerprintIsDeterministic() throws Exception {
        X509Certificate cert = loadTestCert();
        assertEquals(AuditCache.fingerprint(cert), AuditCache.fingerprint(cert));
    }

    @Test
    void firstCallIsNotRecentlyAudited() throws Exception {
        X509Certificate cert = loadTestCert();
        String fp = AuditCache.fingerprint(cert);
        assertFalse(cache.recentlyAudited(fp));
    }

    @Test
    void secondCallWithinTtlIsRecentlyAudited() throws Exception {
        X509Certificate cert = loadTestCert();
        String fp = AuditCache.fingerprint(cert);
        cache.recentlyAudited(fp); // first call — registers
        assertTrue(cache.recentlyAudited(fp)); // second call — cached
    }

    private X509Certificate loadTestCert() throws Exception {
        var factory = java.security.cert.CertificateFactory.getInstance("X.509");
        try (var is = getClass().getResourceAsStream("/ca/intermediate/certs/127.0.0.1.cert.pem")) {
            return (X509Certificate) factory.generateCertificate(is);
        }
    }
}
```

Note: this test needs the test cert on classpath. Copy `sancus-core/src/test/resources/ca/` to `sancus-agent/src/test/resources/ca/` (only the `127.0.0.1.cert.pem` file is needed — copy just that).

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn test -pl sancus-agent -Dtest=AuditCacheTest`

Expected: FAIL — `AuditCache` class does not exist.

- [ ] **Step 3: Write implementation**

```java
package org.brylex.sancus.agent;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.HexFormat;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

public final class AuditCache {

    public static final AuditCache INSTANCE = new AuditCache();

    private final ConcurrentHashMap<String, Instant> cache = new ConcurrentHashMap<>();
    private final AtomicInteger callCount = new AtomicInteger();

    public static String fingerprint(X509Certificate cert) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(cert.getEncoded());
            return HexFormat.of().formatHex(digest);
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute certificate fingerprint", e);
        }
    }

    public boolean recentlyAudited(String fingerprint) {
        Instant now = Instant.now();

        if (callCount.incrementAndGet() % 100 == 0) {
            evictStale(now);
        }

        Instant lastSeen = cache.get(fingerprint);
        if (lastSeen != null && lastSeen.plus(AgentConfig.current().cacheTtl()).isAfter(now)) {
            return true;
        }
        cache.put(fingerprint, now);
        return false;
    }

    private void evictStale(Instant now) {
        var ttl = AgentConfig.current().cacheTtl().multipliedBy(2);
        cache.entrySet().removeIf(e -> e.getValue().plus(ttl).isBefore(now));
    }
}
```

- [ ] **Step 4: Add test cert resource and run test**

```bash
mkdir -p sancus-agent/src/test/resources/ca/intermediate/certs
cp sancus-core/src/test/resources/ca/intermediate/certs/127.0.0.1.cert.pem \
   sancus-agent/src/test/resources/ca/intermediate/certs/
```

Run: `mvn test -pl sancus-agent -Dtest=AuditCacheTest`

Expected: PASS — all 4 tests green.

- [ ] **Step 5: Commit**

```bash
git add sancus-agent/src/main/java/org/brylex/sancus/agent/AuditCache.java \
       sancus-agent/src/test/java/org/brylex/sancus/agent/AuditCacheTest.java \
       sancus-agent/src/test/resources/ca/
git commit -m "feat: add AuditCache with SHA-256 fingerprint deduplication"
```

---

## Task 4: SancusAgentTrustManager — bootstrap shim

**Files:**
- Create: `sancus-agent/src/main/java/org/brylex/sancus/agent/bootstrap/SancusAgentTrustManager.java`
- Create: `sancus-agent/src/test/java/org/brylex/sancus/agent/bootstrap/SancusAgentTrustManagerTest.java`

- [ ] **Step 1: Write the failing test**

```java
package org.brylex.sancus.agent.bootstrap;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BiConsumer;

import static org.junit.jupiter.api.Assertions.*;

class SancusAgentTrustManagerTest {

    @AfterEach
    void clearCallback() {
        SancusAgentTrustManager.setAuditCallback(null);
    }

    @Test
    void delegatesToOriginalTrustManager() throws Exception {
        var delegate = new RecordingExtendedTrustManager();
        var wrapper = new SancusAgentTrustManager(delegate);

        wrapper.checkServerTrusted(new X509Certificate[0], "RSA");
        assertEquals(1, delegate.calls);
    }

    @Test
    void callsAuditCallbackOnSuccess() throws Exception {
        var delegate = new RecordingExtendedTrustManager();
        var wrapper = new SancusAgentTrustManager(delegate);
        List<Boolean> rejections = new ArrayList<>();
        SancusAgentTrustManager.setAuditCallback((chain, rejected) -> rejections.add(rejected));

        wrapper.checkServerTrusted(new X509Certificate[0], "RSA");
        assertEquals(List.of(false), rejections);
    }

    @Test
    void callsAuditCallbackOnRejection() {
        var delegate = new ThrowingExtendedTrustManager();
        var wrapper = new SancusAgentTrustManager(delegate);
        List<Boolean> rejections = new ArrayList<>();
        SancusAgentTrustManager.setAuditCallback((chain, rejected) -> rejections.add(rejected));

        assertThrows(CertificateException.class,
                () -> wrapper.checkServerTrusted(new X509Certificate[0], "RSA"));
        assertEquals(List.of(true), rejections);
    }

    @Test
    void propagatesExceptionFromDelegate() {
        var delegate = new ThrowingExtendedTrustManager();
        var wrapper = new SancusAgentTrustManager(delegate);

        var ex = assertThrows(CertificateException.class,
                () -> wrapper.checkServerTrusted(new X509Certificate[0], "RSA"));
        assertEquals("untrusted", ex.getMessage());
    }

    @Test
    void nonExtendedDelegateFallsBackTo2ArgInSocketOverload() throws Exception {
        var delegate = new RecordingBasicTrustManager();
        var wrapper = new SancusAgentTrustManager(delegate);

        wrapper.checkServerTrusted(new X509Certificate[0], "RSA", (Socket) null);
        assertEquals(1, delegate.calls, "Should have called 2-arg checkServerTrusted");
    }

    @Test
    void auditCallbackExceptionDoesNotAffectDelegation() throws Exception {
        var delegate = new RecordingExtendedTrustManager();
        var wrapper = new SancusAgentTrustManager(delegate);
        SancusAgentTrustManager.setAuditCallback((chain, rejected) -> {
            throw new RuntimeException("audit boom");
        });

        // Should not throw — audit failure is swallowed
        wrapper.checkServerTrusted(new X509Certificate[0], "RSA");
        assertEquals(1, delegate.calls);
    }

    // --- Test doubles ---

    static class RecordingExtendedTrustManager extends X509ExtendedTrustManager {
        int calls;
        public void checkClientTrusted(X509Certificate[] c, String a) {}
        public void checkServerTrusted(X509Certificate[] c, String a) { calls++; }
        public void checkClientTrusted(X509Certificate[] c, String a, Socket s) {}
        public void checkServerTrusted(X509Certificate[] c, String a, Socket s) { calls++; }
        public void checkClientTrusted(X509Certificate[] c, String a, javax.net.ssl.SSLEngine e) {}
        public void checkServerTrusted(X509Certificate[] c, String a, javax.net.ssl.SSLEngine e) { calls++; }
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }

    static class ThrowingExtendedTrustManager extends X509ExtendedTrustManager {
        public void checkClientTrusted(X509Certificate[] c, String a) {}
        public void checkServerTrusted(X509Certificate[] c, String a) throws CertificateException {
            throw new CertificateException("untrusted");
        }
        public void checkClientTrusted(X509Certificate[] c, String a, Socket s) {}
        public void checkServerTrusted(X509Certificate[] c, String a, Socket s) throws CertificateException {
            throw new CertificateException("untrusted");
        }
        public void checkClientTrusted(X509Certificate[] c, String a, javax.net.ssl.SSLEngine e) {}
        public void checkServerTrusted(X509Certificate[] c, String a, javax.net.ssl.SSLEngine e) throws CertificateException {
            throw new CertificateException("untrusted");
        }
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }

    static class RecordingBasicTrustManager implements X509TrustManager {
        int calls;
        public void checkClientTrusted(X509Certificate[] c, String a) {}
        public void checkServerTrusted(X509Certificate[] c, String a) { calls++; }
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn test -pl sancus-agent -Dtest=SancusAgentTrustManagerTest`

Expected: FAIL — class does not exist.

- [ ] **Step 3: Write implementation**

```java
package org.brylex.sancus.agent.bootstrap;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.function.BiConsumer;

public class SancusAgentTrustManager extends X509ExtendedTrustManager {

    private final X509TrustManager delegate;
    private final boolean delegateIsExtended;

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

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException {
        CertificateException thrown = null;
        try {
            if (delegateIsExtended) {
                ((X509ExtendedTrustManager) delegate).checkServerTrusted(chain, authType, socket);
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

    private void fireAudit(X509Certificate[] chain, boolean rejected) {
        BiConsumer<X509Certificate[], Boolean> cb = auditCallback;
        if (cb != null) {
            try {
                cb.accept(chain, rejected);
            } catch (Exception ignored) {
            }
        }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `mvn test -pl sancus-agent -Dtest=SancusAgentTrustManagerTest`

Expected: PASS — all 6 tests green.

- [ ] **Step 5: Commit**

```bash
git add sancus-agent/src/main/java/org/brylex/sancus/agent/bootstrap/SancusAgentTrustManager.java \
       sancus-agent/src/test/java/org/brylex/sancus/agent/bootstrap/SancusAgentTrustManagerTest.java
git commit -m "feat: add SancusAgentTrustManager bootstrap shim with try/finally audit"
```

---

## Task 5: AgentAuditCallback — audit logic in agent classloader

**Files:**
- Create: `sancus-agent/src/main/java/org/brylex/sancus/agent/AgentAuditCallback.java`
- Create: `sancus-agent/src/test/java/org/brylex/sancus/agent/AgentAuditCallbackTest.java`

- [ ] **Step 1: Write the failing test**

```java
package org.brylex.sancus.agent;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

class AgentAuditCallbackTest {

    private Logger logger;
    private TestHandler handler;

    @BeforeEach
    void setUp() {
        logger = Logger.getLogger("sancus");
        handler = new TestHandler();
        logger.addHandler(handler);
        logger.setUseParentHandlers(false);
        AgentConfig.reset();
        // Set log level to OK so we see all findings
        System.setProperty("sancus.log.level", "OK");
    }

    @AfterEach
    void tearDown() {
        logger.removeHandler(handler);
        System.clearProperty("sancus.log.level");
        AgentConfig.reset();
    }

    @Test
    void logsFindings() throws Exception {
        var callback = new AgentAuditCallback();
        X509Certificate cert = loadTestCert();

        callback.accept(new X509Certificate[]{cert}, false);

        assertFalse(handler.records.isEmpty(), "Should have logged at least one finding");
        assertTrue(handler.records.stream().anyMatch(r -> r.getMessage().contains("[sancus]")));
    }

    @Test
    void rejectedHandshakePrefixesWithRejected() throws Exception {
        var callback = new AgentAuditCallback();
        X509Certificate cert = loadTestCert();

        callback.accept(new X509Certificate[]{cert}, true);

        assertTrue(handler.records.stream()
                .anyMatch(r -> r.getMessage().contains("[REJECTED]")),
                "Rejected handshakes should have [REJECTED] prefix");
    }

    @Test
    void deduplicatesWithinTtl() throws Exception {
        var callback = new AgentAuditCallback();
        X509Certificate cert = loadTestCert();

        callback.accept(new X509Certificate[]{cert}, false);
        int countAfterFirst = handler.records.size();

        callback.accept(new X509Certificate[]{cert}, false);
        assertEquals(countAfterFirst, handler.records.size(),
                "Second call with same cert should be deduplicated");
    }

    private X509Certificate loadTestCert() throws Exception {
        var factory = CertificateFactory.getInstance("X.509");
        try (var is = getClass().getResourceAsStream("/ca/intermediate/certs/127.0.0.1.cert.pem")) {
            return (X509Certificate) factory.generateCertificate(is);
        }
    }

    static class TestHandler extends Handler {
        final List<LogRecord> records = new ArrayList<>();
        public void publish(LogRecord record) {
            records.add(record);
        }
        public void flush() {}
        public void close() {}
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn test -pl sancus-agent -Dtest=AgentAuditCallbackTest`

Expected: FAIL — `AgentAuditCallback` does not exist.

- [ ] **Step 3: Write implementation**

```java
package org.brylex.sancus.agent;

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

    private static final Logger logger = Logger.getLogger("sancus");

    @Override
    public void accept(X509Certificate[] chain, Boolean rejected) {
        if (chain == null || chain.length == 0) return;

        String fingerprint = AuditCache.fingerprint(chain[0]);
        if (AuditCache.INSTANCE.recentlyAudited(fingerprint)) return;

        AgentConfig config = AgentConfig.current();
        HandshakeInfo info = new HandshakeInfo(null, null, chain);

        List<Finding> findings = config.checks().stream()
                .flatMap(c -> c.check(info, chain).stream())
                .toList();

        String prefix = Boolean.TRUE.equals(rejected) ? "[REJECTED] " : "";
        findings.stream()
                .filter(f -> f.severity().compareTo(config.minLogLevel()) >= 0)
                .forEach(f -> logger.log(
                        toJulLevel(f.severity()),
                        "[sancus] {0} — {1}{2}",
                        new Object[]{f.severity(), prefix, f.summary()}));
    }

    private static Level toJulLevel(Severity severity) {
        return switch (severity) {
            case OK -> Level.INFO;
            case WARNING -> Level.WARNING;
            case CRITICAL -> Level.WARNING;
        };
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `mvn test -pl sancus-agent -Dtest=AgentAuditCallbackTest`

Expected: PASS — all 3 tests green.

- [ ] **Step 5: Commit**

```bash
git add sancus-agent/src/main/java/org/brylex/sancus/agent/AgentAuditCallback.java \
       sancus-agent/src/test/java/org/brylex/sancus/agent/AgentAuditCallbackTest.java
git commit -m "feat: add AgentAuditCallback with JUL logging and dedup"
```

---

## Task 6: SslContextAdvice + SancusAgent premain

**Files:**
- Create: `sancus-agent/src/main/java/org/brylex/sancus/agent/SslContextAdvice.java`
- Create: `sancus-agent/src/main/java/org/brylex/sancus/agent/SancusAgent.java`

- [ ] **Step 1: Write SslContextAdvice**

```java
package org.brylex.sancus.agent;

import net.bytebuddy.asm.Advice;
import org.brylex.sancus.agent.bootstrap.SancusAgentTrustManager;

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

public class SslContextAdvice {

    @Advice.OnMethodEnter
    static void onInit(@Advice.Argument(value = 1, readOnly = false) TrustManager[] tms) {
        if (tms == null) return;

        TrustManager[] wrapped = new TrustManager[tms.length];
        for (int i = 0; i < tms.length; i++) {
            if (tms[i] instanceof SancusAgentTrustManager) {
                wrapped[i] = tms[i];
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

- [ ] **Step 2: Write SancusAgent premain**

```java
package org.brylex.sancus.agent;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.agent.builder.AgentBuilder.RedefinitionStrategy;
import net.bytebuddy.asm.Advice;
import org.brylex.sancus.agent.bootstrap.SancusAgentTrustManager;

import java.io.IOException;
import java.lang.instrument.Instrumentation;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.logging.Logger;

import static net.bytebuddy.matcher.ElementMatchers.named;

public class SancusAgent {

    private static final Logger logger = Logger.getLogger("sancus");

    public static void premain(String args, Instrumentation inst) throws Exception {
        AgentConfig config = AgentConfig.fromSystemProperties();
        if (!config.enabled()) {
            logger.info("[sancus] Agent disabled via sancus.enabled=false");
            return;
        }

        SancusAgentTrustManager.setAuditCallback(new AgentAuditCallback());

        Path tempDir = Files.createTempDirectory("sancus-agent");
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try (var walk = Files.walk(tempDir)) {
                walk.sorted(Comparator.reverseOrder()).forEach(p -> {
                    try { Files.deleteIfExists(p); } catch (IOException ignored) {}
                });
            } catch (IOException ignored) {}
        }));

        new AgentBuilder.Default()
                .with(RedefinitionStrategy.RETRANSFORMATION)
                .enableBootstrapInjection(inst, tempDir.toFile())
                .type(named("javax.net.ssl.SSLContext"))
                .transform((builder, type, classLoader, module, domain) ->
                        builder.visit(Advice.to(SslContextAdvice.class).on(named("init"))))
                .installOn(inst);

        logger.info("[sancus] Agent installed — intercepting SSLContext.init()");
    }
}
```

- [ ] **Step 3: Build to verify compilation**

Run: `mvn compile -pl sancus-agent`

Expected: BUILD SUCCESS.

- [ ] **Step 4: Commit**

```bash
git add sancus-agent/src/main/java/org/brylex/sancus/agent/SslContextAdvice.java \
       sancus-agent/src/main/java/org/brylex/sancus/agent/SancusAgent.java
git commit -m "feat: add SslContextAdvice and SancusAgent premain with bootstrap injection"
```

---

## Task 7: Integration tests via Maven Failsafe

**Files:**
- Create: `sancus-agent/src/test/java/org/brylex/sancus/agent/SancusAgentIT.java`

These tests run via `mvn verify` with the actual `-javaagent` flag, testing the full premain flow.

- [ ] **Step 1: Write integration test**

```java
package org.brylex.sancus.agent;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

import javax.net.ssl.*;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SancusAgentIT {

    private static HttpsServer server;
    private static int port;
    private static final TestHandler logHandler = new TestHandler();

    @BeforeAll
    static void startServer() throws Exception {
        // Register log handler
        Logger sancusLogger = Logger.getLogger("sancus");
        sancusLogger.addHandler(logHandler);
        sancusLogger.setUseParentHandlers(false);

        // Load test keystore
        KeyStore ks = KeyStore.getInstance("JKS");
        try (var is = SancusAgentIT.class.getResourceAsStream("/jks/selfsigned.jks")) {
            ks.load(is, "changeit".toCharArray());
        }

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, "changeit".toCharArray());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        server = HttpsServer.create(new InetSocketAddress(0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(sslContext));
        server.createContext("/test", exchange -> {
            byte[] response = "OK".getBytes();
            exchange.sendResponseHeaders(200, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });
        server.start();
        port = server.getAddress().getPort();
    }

    @AfterAll
    static void stopServer() {
        if (server != null) server.stop(0);
    }

    @Test
    void agentInterceptsTlsHandshakeAndLogsFinding() throws Exception {
        logHandler.records.clear();

        // Create SSLContext that trusts the self-signed cert
        KeyStore trustStore = KeyStore.getInstance("JKS");
        try (var is = getClass().getResourceAsStream("/jks/selfsigned.jks")) {
            trustStore.load(is, "changeit".toCharArray());
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        SSLContext clientCtx = SSLContext.getInstance("TLS");
        clientCtx.init(null, tmf.getTrustManagers(), null);

        HttpClient client = HttpClient.newBuilder()
                .sslContext(clientCtx)
                .build();

        HttpResponse<String> response = client.send(
                HttpRequest.newBuilder(URI.create("https://localhost:" + port + "/test")).build(),
                HttpResponse.BodyHandlers.ofString());

        assertEquals(200, response.statusCode());

        // Verify findings were logged
        assertTrue(logHandler.records.stream()
                        .anyMatch(r -> r.getMessage().contains("[sancus]")),
                "Expected [sancus] log entries but got: " + logHandler.records);
    }

    @Test
    void agentLogsRejectedHandshake() {
        logHandler.records.clear();

        // Use default trust manager which will NOT trust self-signed cert
        assertThrows(Exception.class, () -> {
            SSLContext clientCtx = SSLContext.getInstance("TLS");
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init((KeyStore) null); // system defaults — won't trust self-signed
            clientCtx.init(null, tmf.getTrustManagers(), null);

            HttpClient client = HttpClient.newBuilder()
                    .sslContext(clientCtx)
                    .build();

            client.send(
                    HttpRequest.newBuilder(URI.create("https://localhost:" + port + "/test")).build(),
                    HttpResponse.BodyHandlers.ofString());
        });

        assertTrue(logHandler.records.stream()
                        .anyMatch(r -> r.getMessage().contains("[REJECTED]")),
                "Expected [REJECTED] log entries but got: " + logHandler.records);
    }

    static class TestHandler extends Handler {
        final List<LogRecord> records = new ArrayList<>();
        public void publish(LogRecord record) {
            // Format the message to resolve parameters
            String msg = record.getMessage();
            if (record.getParameters() != null) {
                msg = java.text.MessageFormat.format(msg, record.getParameters());
            }
            records.add(new LogRecord(record.getLevel(), msg));
        }
        public void flush() {}
        public void close() {}
    }
}
```

- [ ] **Step 2: Add test keystore resource**

The integration test needs a self-signed JKS. Copy from core test resources:

```bash
mkdir -p sancus-agent/src/test/resources/jks
cp sancus-core/src/test/resources/jks/selfsigned.jks sancus-agent/src/test/resources/jks/
```

If `selfsigned.jks` doesn't exist in core, generate one:

```bash
keytool -genkeypair -alias test -keyalg RSA -keysize 2048 \
  -dname "CN=localhost" -validity 365 -storetype JKS \
  -keystore sancus-agent/src/test/resources/jks/selfsigned.jks \
  -storepass changeit -keypass changeit
```

- [ ] **Step 3: Set log level for IT tests**

Set `sancus.log.level=OK` in Failsafe config so all findings are visible:

In `sancus-agent/pom.xml`, update the Failsafe plugin config:

```xml
<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-failsafe-plugin</artifactId>
    <version>3.5.3</version>
    <configuration>
        <argLine>-javaagent:${project.build.directory}/${project.build.finalName}.jar</argLine>
        <systemPropertyVariables>
            <sancus.log.level>OK</sancus.log.level>
        </systemPropertyVariables>
    </configuration>
    <executions>
        <execution>
            <goals>
                <goal>integration-test</goal>
                <goal>verify</goal>
            </goals>
        </execution>
    </executions>
</plugin>
```

- [ ] **Step 4: Package and run integration tests**

Run: `mvn verify -pl sancus-agent`

Expected: BUILD SUCCESS — both IT tests pass. The agent JAR is built first (package phase), then Failsafe launches a new JVM with `-javaagent:sancus-agent.jar` and runs the IT tests.

If Failsafe fails because the shade JAR isn't built yet when Failsafe runs, ensure `package` phase runs before `integration-test` (it should by default in the Maven lifecycle).

- [ ] **Step 5: Commit**

```bash
git add sancus-agent/src/test/java/org/brylex/sancus/agent/SancusAgentIT.java \
       sancus-agent/src/test/resources/jks/ \
       sancus-agent/pom.xml
git commit -m "test: add integration tests for premain agent with Failsafe"
```

---

## Task 8: Full build verification

- [ ] **Step 1: Clean build of all modules**

Run: `mvn clean verify`

Expected: BUILD SUCCESS for all three modules.

- [ ] **Step 2: Verify agent JAR manifest**

Run: `unzip -p sancus-agent/target/sancus-agent-develop-SNAPSHOT.jar META-INF/MANIFEST.MF | grep Premain-Class`

Expected: `Premain-Class: org.brylex.sancus.agent.SancusAgent`

- [ ] **Step 3: Verify agent JAR doesn't contain CLI deps**

Run: `jar tf sancus-agent/target/sancus-agent-develop-SNAPSHOT.jar | grep -E "(logback|picocli|jansi)" && echo "FAIL" || echo "OK"`

Expected: `OK`

- [ ] **Step 4: Verify CLI JAR still works**

Run: `java -jar sancus-cli/target/sancus-cli-develop-SNAPSHOT.jar --help`

Expected: picocli help output showing `resolve` and `audit` subcommands.

- [ ] **Step 5: Commit (if any fixes were needed)**

```bash
git add -A
git commit -m "chore: verify full build — all modules pass"
```
