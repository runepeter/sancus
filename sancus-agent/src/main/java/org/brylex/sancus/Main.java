package org.brylex.sancus;

import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.net.JksOptions;
import io.vertx.rxjava.core.AbstractVerticle;
import io.vertx.rxjava.core.http.HttpClientRequest;
import io.vertx.rxjava.ext.web.Router;
import io.vertx.rxjava.ext.web.RoutingContext;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.net.UnknownHostException;
import java.security.*;
import java.util.concurrent.TimeoutException;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 09/04/2017.
 */
public class Main {

    private static Logger logger = LoggerFactory.getLogger(Main.class);

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {

        int port = Integer.parseInt(System.getProperty("port", "8080"));

        System.setProperty("vertx.logger-delegate-factory-class-name", "io.vertx.core.logging.SLF4JLogDelegateFactory");

        Vertx.vertx().deployVerticle(new MainVerticle(port));
    }

    private static class MainVerticle extends AbstractVerticle {

        private final int port;
        private Logger logger = LoggerFactory.getLogger(MainVerticle.class);

        private MainVerticle(int port) {
            this.port = port;
        }

        @Override
        public void start() throws Exception {

            Router router = initRouter();

            vertx.createHttpServer()
                    .requestHandler(router::accept)
                    .rxListen(port).subscribe(
                    server -> {
                        logger.info("Server started!");
                    },
                    failure -> {
                        logger.error("Unable to start server.", failure);
                    }
            );
        }

        private Router initRouter() {

            Router router = Router.router(vertx);

            router.get().produces("application/json").handler(this::handleGet);

            return router;
        }


        private void handleGet(RoutingContext context) {

            JksOptions trustOptions = new JksOptions();
            trustOptions.setPath("sancus-agent/full.jks");
            trustOptions.setPassword("changeit");

            HttpClientOptions options = new HttpClientOptions();
            options.setSsl(true);
            options.setTrustOptions(new SancusTrustOptions(trustOptions));

            HttpClientRequest request = vertx.createHttpClient(options).request(HttpMethod.GET, 443, "aws.amazon.com", "/");
            request.setTimeout(5000).toObservable().subscribe(
                    r -> {
                        context.response().end(r.statusMessage());
                    },
                    e -> {
                        if (e instanceof UnknownHostException) {
                            context.response().end("UNKNOWN_HOST(...)");
                        } else if (e instanceof TimeoutException) {
                            context.response().end("NOT_LISTENING(...)");
                        } else if (e instanceof SSLHandshakeException) {

                            e.printStackTrace();

                            context.response().end("SSL_HANDSHAKE(...)");
                        } else {
                            e.printStackTrace();
                            context.response().end("ERROR");
                        }
                    }
            );
            request.end();
            logger.info("BALLA");
        }
    }

}
