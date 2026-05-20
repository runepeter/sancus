# Sancus First Release Preparation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Konfigurer sancus (multi-module Maven-prosjekt) for sin første release til Maven Central via Central Portal, basert på xmlgen som mal.

**Architecture:** All releaserelatert konfig samles i parent pom (`sancus/pom.xml`). Modulene (`sancus-core`, `sancus-agent`, `sancus-cli`) arver plugin-versjoner og release-profil. GPG-signering og Central Portal-publisering er inline i parent — ikke avhengig av global `~/.m2/settings.xml` utenom server-credentials.

**Tech Stack:** Maven 3.9+, JDK 25, maven-release-plugin, maven-gpg-plugin, central-publishing-maven-plugin, maven-source-plugin, maven-javadoc-plugin.

**Out of scope:**
- Selve release-utførelsen (`mvn release:prepare` / `release:perform`)
- README.md og LICENSE-fil i sancus-roten
- Endre `<groupId>` (beholder `org.brylex`)
- Endre Java-versjon (beholder 25)

**Versjonsstrategi:** `develop-SNAPSHOT` → `0.1-SNAPSHOT` (første release blir `sancus-0.1`).

---

## File Structure

**Modified:**
- `sancus/pom.xml` — Full omskriving med metadata, pluginManagement, release-profil
- `sancus/sancus-core/pom.xml` — Fjern plugin-versjoner som nå arves
- `sancus/sancus-agent/pom.xml` — Fjern plugin-versjoner som nå arves
- `sancus/sancus-cli/pom.xml` — Fjern plugin-versjoner som nå arves

**Created:**
- `sancus/RELEASING.md` — Releaseprosedyre, tilpasset multi-module

---

### Task 1: Skriv om parent pom.xml

**Files:**
- Modify: `sancus/pom.xml` (full omskriving)

- [ ] **Step 1: Skriv om `sancus/pom.xml`**

Erstatt hele filen med:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">

    <modelVersion>4.0.0</modelVersion>

    <groupId>org.brylex</groupId>
    <artifactId>sancus</artifactId>
    <version>0.1-SNAPSHOT</version>
    <packaging>pom</packaging>

    <name>Sancus</name>
    <description>TLS certificate chain inspection and resolution toolkit — library, java agent, and CLI.</description>
    <url>https://github.com/runepeter/sancus</url>

    <organization>
        <name>Brylex org.</name>
        <url>http://www.brylex.org</url>
    </organization>

    <licenses>
        <license>
            <name>The Apache Software License, Version 2.0</name>
            <url>http://www.apache.org/licenses/LICENSE-2.0.txt</url>
            <distribution>repo</distribution>
        </license>
    </licenses>

    <scm>
        <connection>scm:git:git://github.com/runepeter/sancus.git</connection>
        <developerConnection>scm:git:ssh://git@github.com/runepeter/sancus.git</developerConnection>
        <url>https://github.com/runepeter/sancus</url>
        <tag>HEAD</tag>
    </scm>

    <developers>
        <developer>
            <id>runepeter</id>
            <name>Rune Peter Bjørnstad</name>
            <email>runepeter@gmail.com</email>
            <roles>
                <role>Developer</role>
            </roles>
        </developer>
    </developers>

    <modules>
        <module>sancus-core</module>
        <module>sancus-agent</module>
        <module>sancus-cli</module>
    </modules>

    <properties>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
        <project.reporting.outputEncoding>UTF-8</project.reporting.outputEncoding>

        <java.version>25</java.version>
        <maven.compiler.release>${java.version}</maven.compiler.release>

        <maven-compiler-plugin.version>3.15.0</maven-compiler-plugin.version>
        <maven-surefire-plugin.version>3.5.5</maven-surefire-plugin.version>
        <maven-failsafe-plugin.version>3.5.5</maven-failsafe-plugin.version>
        <maven-jar-plugin.version>3.4.2</maven-jar-plugin.version>
        <maven-shade-plugin.version>3.6.0</maven-shade-plugin.version>
        <maven-source-plugin.version>3.3.1</maven-source-plugin.version>
        <maven-javadoc-plugin.version>3.12.0</maven-javadoc-plugin.version>
        <maven-gpg-plugin.version>3.2.7</maven-gpg-plugin.version>
        <maven-release-plugin.version>3.3.1</maven-release-plugin.version>
        <central-publishing-maven-plugin.version>0.10.0</central-publishing-maven-plugin.version>
    </properties>

    <build>
        <pluginManagement>
            <plugins>
                <plugin>
                    <groupId>org.apache.maven.plugins</groupId>
                    <artifactId>maven-compiler-plugin</artifactId>
                    <version>${maven-compiler-plugin.version}</version>
                </plugin>
                <plugin>
                    <groupId>org.apache.maven.plugins</groupId>
                    <artifactId>maven-surefire-plugin</artifactId>
                    <version>${maven-surefire-plugin.version}</version>
                </plugin>
                <plugin>
                    <groupId>org.apache.maven.plugins</groupId>
                    <artifactId>maven-failsafe-plugin</artifactId>
                    <version>${maven-failsafe-plugin.version}</version>
                </plugin>
                <plugin>
                    <groupId>org.apache.maven.plugins</groupId>
                    <artifactId>maven-jar-plugin</artifactId>
                    <version>${maven-jar-plugin.version}</version>
                </plugin>
                <plugin>
                    <groupId>org.apache.maven.plugins</groupId>
                    <artifactId>maven-shade-plugin</artifactId>
                    <version>${maven-shade-plugin.version}</version>
                </plugin>
            </plugins>
        </pluginManagement>

        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-compiler-plugin</artifactId>
            </plugin>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-release-plugin</artifactId>
                <version>${maven-release-plugin.version}</version>
                <configuration>
                    <tagNameFormat>sancus-@{project.version}</tagNameFormat>
                    <releaseProfiles>release</releaseProfiles>
                    <autoVersionSubmodules>true</autoVersionSubmodules>
                </configuration>
            </plugin>
        </plugins>
    </build>

    <profiles>
        <profile>
            <id>release</id>
            <build>
                <plugins>
                    <plugin>
                        <groupId>org.apache.maven.plugins</groupId>
                        <artifactId>maven-source-plugin</artifactId>
                        <version>${maven-source-plugin.version}</version>
                        <executions>
                            <execution>
                                <id>attach-sources</id>
                                <goals>
                                    <goal>jar-no-fork</goal>
                                </goals>
                            </execution>
                        </executions>
                    </plugin>
                    <plugin>
                        <groupId>org.apache.maven.plugins</groupId>
                        <artifactId>maven-javadoc-plugin</artifactId>
                        <version>${maven-javadoc-plugin.version}</version>
                        <configuration>
                            <doclint>none</doclint>
                            <quiet>true</quiet>
                        </configuration>
                        <executions>
                            <execution>
                                <id>attach-javadocs</id>
                                <goals>
                                    <goal>jar</goal>
                                </goals>
                            </execution>
                        </executions>
                    </plugin>
                    <plugin>
                        <groupId>org.apache.maven.plugins</groupId>
                        <artifactId>maven-gpg-plugin</artifactId>
                        <version>${maven-gpg-plugin.version}</version>
                        <executions>
                            <execution>
                                <id>sign-artifacts</id>
                                <phase>verify</phase>
                                <goals>
                                    <goal>sign</goal>
                                </goals>
                            </execution>
                        </executions>
                    </plugin>
                    <plugin>
                        <groupId>org.sonatype.central</groupId>
                        <artifactId>central-publishing-maven-plugin</artifactId>
                        <version>${central-publishing-maven-plugin.version}</version>
                        <extensions>true</extensions>
                        <configuration>
                            <publishingServerId>central</publishingServerId>
                            <autoPublish>false</autoPublish>
                        </configuration>
                    </plugin>
                </plugins>
            </build>
        </profile>
    </profiles>

</project>
```

- [ ] **Step 2: Verifiser at standardbygg fortsatt går**

Run: `mvn -q -DskipTests install`
Expected: BUILD SUCCESS for parent + alle 3 moduler.

- [ ] **Step 3: Commit**

```bash
git add pom.xml
git commit -m "build: legg til release-metadata og pluginManagement i parent pom"
```

---

### Task 2: Rydd sancus-core/pom.xml

**Files:**
- Modify: `sancus/sancus-core/pom.xml`

- [ ] **Step 1: Fjern eksplisitte plugin-versjoner**

I `sancus-core/pom.xml`, fjern `<version>` for `maven-surefire-plugin` (linje 42) og `maven-jar-plugin` (linje 47). Disse arves nå fra parent pluginManagement.

Resultat (build-seksjonen blir):

```xml
<build>
    <plugins>
        <plugin>
            <groupId>org.apache.maven.plugins</groupId>
            <artifactId>maven-surefire-plugin</artifactId>
        </plugin>
        <plugin>
            <groupId>org.apache.maven.plugins</groupId>
            <artifactId>maven-jar-plugin</artifactId>
            <executions>
                <execution>
                    <goals>
                        <goal>test-jar</goal>
                    </goals>
                </execution>
            </executions>
        </plugin>
    </plugins>
</build>
```

- [ ] **Step 2: Verifiser bygg**

Run: `mvn -q -DskipTests -pl sancus-core -am install`
Expected: BUILD SUCCESS

- [ ] **Step 3: Commit**

```bash
git add sancus-core/pom.xml
git commit -m "build: arv plugin-versjoner i sancus-core"
```

---

### Task 3: Rydd sancus-agent/pom.xml

**Files:**
- Modify: `sancus/sancus-agent/pom.xml`

- [ ] **Step 1: Fjern eksplisitte plugin-versjoner**

I `sancus-agent/pom.xml`, fjern `<version>` for `maven-surefire-plugin`, `maven-shade-plugin`, og `maven-failsafe-plugin`. Behold all annen konfig (manifest-entries, argLine, etc).

- [ ] **Step 2: Verifiser bygg**

Run: `mvn -q -pl sancus-agent -am install`
Expected: BUILD SUCCESS (inkludert integration tests siden agentet brukes via `-javaagent:`).

- [ ] **Step 3: Commit**

```bash
git add sancus-agent/pom.xml
git commit -m "build: arv plugin-versjoner i sancus-agent"
```

---

### Task 4: Rydd sancus-cli/pom.xml

**Files:**
- Modify: `sancus/sancus-cli/pom.xml`

- [ ] **Step 1: Fjern eksplisitte plugin-versjoner**

I `sancus-cli/pom.xml`, fjern `<version>` for `maven-surefire-plugin` og `maven-shade-plugin`.

- [ ] **Step 2: Verifiser bygg**

Run: `mvn -q -pl sancus-cli -am install`
Expected: BUILD SUCCESS

- [ ] **Step 3: Commit**

```bash
git add sancus-cli/pom.xml
git commit -m "build: arv plugin-versjoner i sancus-cli"
```

---

### Task 5: Lag RELEASING.md

**Files:**
- Create: `sancus/RELEASING.md`

- [ ] **Step 1: Skriv RELEASING.md**

Innholdet er en multi-module-tilpasset versjon av xmlgens RELEASING.md. Bytt ut `xmlgen` med `sancus` i tags, kommandoer og referanser. Forklar at `mvn -Prelease deploy` fra parent vil signere og laste opp alle tre modulene (parent pom + sancus-core + sancus-agent + sancus-cli) som ett bundle.

Bruk strukturen fra `~/workspace/runepeter/xmlgen/RELEASING.md` som mal:
- One-time setup (Central Portal-konto, user token i `~/.m2/settings.xml`, GPG-nøkkel, keyserver upload)
- Cutting a release (`mvn release:prepare` + `release:perform`, eller `mvn -Prelease clean deploy` direkte)
- Reviewing and publishing (deployments havner som VALIDATED, må publiseres manuelt)
- After publishing (push tag + GitHub Release)
- Troubleshooting (`Invalid signature ... Could not find a public key`)
- Versioning (`sancus-<version>`-tags, pre-1.0)

- [ ] **Step 2: Commit**

```bash
git add RELEASING.md
git commit -m "docs: legg til RELEASING.md for sancus"
```

---

### Task 6: End-to-end verifisering

- [ ] **Step 1: Verifiser standard bygg**

Run: `mvn -q clean verify`
Expected: BUILD SUCCESS for alle 3 moduler.

- [ ] **Step 2: Verifiser release-profil (uten deploy)**

Run: `mvn -q -Prelease clean package -DskipTests -Dgpg.skip=true`
Expected: BUILD SUCCESS. Output skal inneholde `-sources.jar` og `-javadoc.jar` for hver modul.

Sjekk:
```bash
find . -name "*-sources.jar" -o -name "*-javadoc.jar" | sort
```
Expected: Hver av sancus-core/sancus-agent/sancus-cli skal ha både `-sources.jar` og `-javadoc.jar` i sin `target/`.

- [ ] **Step 3: Bekreft GPG-signering virker (manuelt, valgfritt)**

Hvis GPG er satt opp:
```bash
mvn -q -Prelease clean package -DskipTests
find . -name "*.asc" | sort
```
Expected: `.asc`-fil per artifact, sources og javadoc.

- [ ] **Step 4: Sluttkommit (hvis det er noe igjen)**

Sannsynligvis ingenting — alle endringer er allerede commitet i tidligere tasks.

---

## Self-Review

**Spec coverage:**
- ✅ Parent pom har metadata for Maven Central (name, description, url, licenses, scm, developers)
- ✅ GPG-config er inline i pom (ikke avhengig av global settings.xml)
- ✅ Release-profil med source/javadoc/gpg/central-publishing — speilbilde av xmlgen
- ✅ maven-release-plugin med korrekt tagNameFormat
- ✅ pluginManagement i parent → modulene arver
- ✅ RELEASING.md med GPG-keyserver-instruks (vanligste fallgruve)

**Placeholder scan:** Ingen TBD/TODO. Alle pom-blokker er konkrete.

**Type consistency:** Plugin-versjoner brukt i parent properties brukes konsistent på tvers av modulene.
