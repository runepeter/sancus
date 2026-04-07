package org.brylex.sancus.agent;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import org.brylex.sancus.agent.bootstrap.SancusAgentTrustManager;

import java.io.IOException;
import java.lang.instrument.Instrumentation;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.logging.Logger;

import static net.bytebuddy.agent.builder.AgentBuilder.RedefinitionStrategy;
import static net.bytebuddy.matcher.ElementMatchers.named;

public class SancusAgent {

    private static final Logger logger = Logger.getLogger("sancus");

    public static void premain(String args, Instrumentation inst) throws Exception {
        AgentConfig config = AgentConfig.fromSystemProperties();
        if (!config.enabled()) {
            logger.info("[sancus] Agent disabled via sancus.enabled=false");
            return;
        }

        // Set audit callback (agent classloader)
        SancusAgentTrustManager.auditCallback = new AgentAuditCallback();

        // Bootstrap injection temp dir
        Path tempDir = Files.createTempDirectory("sancus-agent");
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try (var walk = Files.walk(tempDir)) {
                walk.sorted(Comparator.reverseOrder()).forEach(p -> {
                    try { Files.deleteIfExists(p); } catch (IOException ignored) {}
                });
            } catch (IOException ignored) {}
        }));

        // Install instrumentation
        new AgentBuilder.Default()
            .with(RedefinitionStrategy.RETRANSFORMATION)
            .with(new AgentBuilder.InjectionStrategy.UsingInstrumentation(inst, tempDir.toFile()))
            .type(named("javax.net.ssl.SSLContext"))
            .transform((builder, type, classLoader, module, domain) ->
                builder.visit(Advice.to(SslContextAdvice.class).on(named("init"))))
            .installOn(inst);

        logger.info("[sancus] Agent installed — intercepting SSLContext.init()");
    }
}
