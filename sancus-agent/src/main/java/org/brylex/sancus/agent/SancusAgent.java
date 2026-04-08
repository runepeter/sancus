package org.brylex.sancus.agent;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import org.brylex.sancus.agent.bootstrap.SancusAgentTrustManager;

import java.io.IOException;
import java.io.InputStream;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.logging.Logger;

import static net.bytebuddy.agent.builder.AgentBuilder.RedefinitionStrategy;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.none;

public class SancusAgent {

    private static final Logger logger = Logger.getLogger("sancus");

    public static void premain(String args, Instrumentation inst) throws Exception {
        AgentConfig config = AgentConfig.fromSystemProperties();
        if (!config.enabled()) {
            logger.info("[sancus] Agent disabled via sancus.enabled=false");
            return;
        }

        // Bootstrap injection temp dir
        Path tempDir = Files.createTempDirectory("sancus-agent");
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try (var walk = Files.walk(tempDir)) {
                walk.sorted(Comparator.reverseOrder()).forEach(p -> {
                    try { Files.deleteIfExists(p); } catch (IOException ignored) {}
                });
            } catch (IOException ignored) {}
        }));

        // Inject SancusAgentTrustManager into bootstrap classloader
        injectBootstrapClass(inst, tempDir,
                "org/brylex/sancus/agent/bootstrap/SancusAgentTrustManager.class");

        // Set audit callback BEFORE installOn to avoid race window where
        // SSLContext.init() fires before callback is set
        AgentAuditCallback callback = new AgentAuditCallback();
        SancusAgentTrustManager.auditCallback = callback;
        setBootstrapField("auditCallback", callback, "audit may not work");

        // Wire AIA resolve callback (if enabled)
        if (config.aiaResolveEnabled()) {
            AgentResolveCallback resolveCallback = new AgentResolveCallback();
            SancusAgentTrustManager.resolveCallback = resolveCallback;
            setBootstrapField("resolveCallback", resolveCallback, "AIA resolve will not work");
            logger.info("[sancus] AIA resolve enabled");
        }

        // Install instrumentation
        new AgentBuilder.Default()
            .ignore(none())
            .with(RedefinitionStrategy.RETRANSFORMATION)
            .with(new AgentBuilder.InjectionStrategy.UsingInstrumentation(inst, tempDir.toFile()))
            .type(named("javax.net.ssl.SSLContext"))
            .transform((builder, type, classLoader, module, domain) ->
                builder.visit(Advice.to(SslContextAdvice.class).on(named("init"))))
            .installOn(inst);

        logger.info("[sancus] Agent installed — intercepting SSLContext.init()");
    }

    private static void setBootstrapField(String fieldName, Object value, String context) {
        try {
            Class<?> bootstrapCopy = Class.forName(
                    "org.brylex.sancus.agent.bootstrap.SancusAgentTrustManager", true, null);
            if (bootstrapCopy != SancusAgentTrustManager.class) {
                bootstrapCopy.getField(fieldName).set(null, value);
            }
        } catch (ClassNotFoundException e) {
            logger.warning("[sancus] Bootstrap copy not found — " + context + ": " + e.getMessage());
        } catch (ReflectiveOperationException e) {
            logger.warning("[sancus] Failed to set " + fieldName + " on bootstrap copy: " + e.getMessage());
        }
    }

    private static void injectBootstrapClass(Instrumentation inst, Path tempDir, String... classResources)
            throws IOException {
        Path jarPath = tempDir.resolve("sancus-bootstrap.jar");
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(jarPath))) {
            for (String resource : classResources) {
                try (InputStream is = SancusAgent.class.getClassLoader().getResourceAsStream(resource)) {
                    if (is == null) throw new IOException("Resource not found: " + resource);
                    jos.putNextEntry(new JarEntry(resource));
                    is.transferTo(jos);
                    jos.closeEntry();
                }
            }
        }
        inst.appendToBootstrapClassLoaderSearch(new java.util.jar.JarFile(jarPath.toFile()));
    }
}
