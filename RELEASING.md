# Releasing sancus

Sancus is a multi-module Maven project (parent + `sancus-core`, `sancus-agent`,
`sancus-cli`). All four artifacts ship together to Maven Central via the
[Central Portal][portal] (the successor to OSSRH, which was sunset in 2025).
Releases are signed with GPG and include sources and Javadoc jars, which
Central requires for every published module.

[portal]: https://central.sonatype.com/

## One-time setup

1. **Central Portal account.** Sign in to https://central.sonatype.com/
   and verify ownership of the `org.brylex` namespace (DNS TXT record or
   GitHub-username-based verification).
2. **Generate a Portal user token.** Profile → "Generate User Token".
   You get a `username` / `password` pair scoped to publishing.
3. **Add the token to `~/.m2/settings.xml`:**

   ```xml
   <settings>
     <servers>
       <server>
         <id>central</id>
         <username>${env.CENTRAL_USERNAME}</username>
         <password>${env.CENTRAL_PASSWORD}</password>
       </server>
     </servers>
   </settings>
   ```

   Set the environment variables in your shell (or use literal values
   directly — but prefer env vars or a credential manager).
4. **GPG key.** Generate one if you don't have it:

   ```bash
   gpg --full-generate-key                       # RSA 4096, no expiry
   gpg --list-secret-keys --keyid-format=long
   ```

   The `sec` line shows your key id, e.g. `sec rsa4096/AB12CD34EF567890`.

5. **Publish your public key to a keyserver Central can poll.** This
   is the easy thing to forget — Central validates each `.asc` signature
   by looking up the corresponding public key on the keyservers below.
   If it can't find a matching fingerprint, the deployment fails with
   `Invalid signature ... Could not find a public key by the key
   fingerprint`. Upload to **both** of these:

   ```bash
   gpg --keyserver keyserver.ubuntu.com --send-keys <KEY_ID>
   gpg --keyserver keys.openpgp.org    --send-keys <KEY_ID>
   ```

   `keyserver.ubuntu.com` is the most reliable — it publishes the key
   (and the UID/email it's bound to) immediately, no verification step.
   `keys.openpgp.org` requires you to **click a confirmation link in an
   email** before it exposes the UID; until then the key is reachable
   by fingerprint but Central may not consider it valid. Doing both
   gives you redundancy.

   Verify the upload propagated (usually within 30–60 seconds):

   ```bash
   gpg --keyserver keyserver.ubuntu.com --recv-keys <KEY_ID>
   ```

   The `maven-gpg-plugin` will use your default key during the release
   build. If you have multiple keys, set `-Dgpg.keyname=<KEY_ID>`.

## Cutting a release

The `release` profile attaches sources, Javadoc, and signatures for **every**
module, and hands the whole reactor bundle to the Central Portal plugin in
a single upload.

The simplest flow uses `maven-release-plugin`:

```bash
# from a clean checkout of master
mvn -B release:prepare        # bumps version in all modules, tags as
                              # sancus-<version>, then bumps to the
                              # next -SNAPSHOT
mvn -B release:perform        # checks out the tag and runs:
                              #   mvn -Prelease deploy
```

`release:perform` invokes the `release` profile, which signs every module's
artifacts and uploads them to the Central Portal as one "deployment"
pending your review.

Alternatively, to publish a one-off version without changing the
project version on `master`:

```bash
mvn -Prelease clean deploy
```

## Reviewing and publishing

By default, deployments are uploaded but **not** published — they sit in
the Central Portal as `VALIDATED`. Visit
https://central.sonatype.com/publishing/deployments, inspect the bundle
(parent pom + `sancus-core`, `sancus-agent`, `sancus-cli`), and click
**Publish** to release everything to Maven Central in one go.

To skip the review step and publish automatically when validation passes,
set `<autoPublish>true</autoPublish>` on the
`central-publishing-maven-plugin` in `pom.xml`.

## After publishing

- Push the release commit and tag created by `release:prepare`:
  ```bash
  git push origin master --follow-tags
  ```
- Create a GitHub Release from the tag (the `gh` CLI works, or do it in
  the UI). Consider attaching the shaded `sancus-agent` and `sancus-cli`
  jars as release assets so users can download a working binary directly
  from GitHub.
- Maven Central indexes new artifacts within ~10–30 minutes; full search
  indexing can take a few hours.

## Troubleshooting

### `Invalid signature ... Could not find a public key by the key fingerprint`

Central uploaded the bundle, validated the signatures cryptographically,
but couldn't fetch the matching public key from any of its keyservers.
You forgot to publish the public half of your GPG key — see step 5 of
the one-time setup. Run the `gpg --send-keys` commands and retry.

Because `release:prepare` has already created the tag and bumped
`master` to the next `-SNAPSHOT`, **don't** run `release:prepare` again.
Instead:

1. Delete the failed deployment in
   https://central.sonatype.com/publishing/deployments (otherwise
   duplicates can show up).
2. Re-deploy from the existing tag:

   ```bash
   git checkout sancus-<version>
   mvn -Prelease clean deploy
   git checkout master
   ```

If `target/checkout/release.properties` from the failed
`release:perform` is still intact, `mvn release:perform` will also do
the right thing — it re-checks out the tag and re-deploys.

### A module's `dependency-reduced-pom.xml` is being deployed instead of the original

This is expected for `sancus-agent` and `sancus-cli` — they use the
`maven-shade-plugin`, which replaces the deployed pom with a
dependency-reduced one. Consumers pulling these modules as a Maven
dependency will get the shaded jar (all transitive deps inlined) and a
pom that lists no runtime dependencies. That is the intended behavior
for the agent and CLI distributions; the library API for consumers is
`sancus-core`.

## Versioning

- Tags follow `sancus-<version>` (e.g. `sancus-0.1`). The release plugin
  is configured with this format.
- `master` always carries the next `-SNAPSHOT` version.
- `autoVersionSubmodules` is enabled, so all four poms (parent + 3
  modules) bump together.
- This project is pre-1.0; treat any release as potentially containing
  breaking changes until 1.0 ships.
