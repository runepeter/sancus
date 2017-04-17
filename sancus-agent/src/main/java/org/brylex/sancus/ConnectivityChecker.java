package org.brylex.sancus;

import io.vertx.core.Handler;
import io.vertx.rxjava.core.RxHelper;
import io.vertx.rxjava.core.Vertx;
import io.vertx.rxjava.core.http.HttpClient;
import io.vertx.rxjava.core.http.HttpClientRequest;
import io.vertx.rxjava.core.http.HttpClientResponse;
import rx.Observable;

import javax.net.ssl.SSLContext;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 09/04/2017.
 */
public class ConnectivityChecker {

    private final Vertx vertx;

    public ConnectivityChecker(Vertx vertx) {
        this.vertx = vertx;
    }

    public String jalla() {

        final HttpClient client = vertx.createHttpClient();

        Observable<HttpClientResponse> observable = RxHelper.get(client, "http://www.vg.no");

        observable.subscribe(r -> {

        }, e -> {

        });

        return null;
    }
}
