package org.brylex.sancus;

import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.impl.VertxInternal;
import io.vertx.core.json.JsonObject;
import io.vertx.core.net.JksOptions;
import io.vertx.core.net.TrustOptions;
import io.vertx.core.net.impl.KeyStoreHelper;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import java.nio.file.Path;
import java.security.KeyStore;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 14/04/2017.
 */
public class SancusTrustOptions extends JksOptions {

    private final JksOptions delegate;
    private CertificateChain.Callback callback;

    public SancusTrustOptions(JksOptions delegate) {
        this.delegate = delegate;
    }

    @Override
    public JsonObject toJson() {
        return delegate.toJson();
    }

    @Override
    public String getPassword() {
        return delegate.getPassword();
    }

    @Override
    public JksOptions setPassword(String password) {
        return delegate.setPassword(password);
    }

    @Override
    public String getPath() {
        return delegate.getPath();
    }

    @Override
    public JksOptions setPath(String path) {
        return delegate.setPath(path);
    }

    @Override
    public Buffer getValue() {
        return delegate.getValue();
    }

    @Override
    public JksOptions setValue(Buffer value) {
        return delegate.setValue(value);
    }

    public CertificateChain.Callback getCallback() {
        return callback;
    }

    public void setCallback(CertificateChain.Callback callback) {
        this.callback = callback;
    }

    @Override
    public boolean equals(Object o) {
        return delegate.equals(o);
    }

    @Override
    public int hashCode() {
        return delegate.hashCode();
    }

    @Override
    public JksOptions clone() {
        return delegate.clone();
    }

    @Override
    public KeyManagerFactory getKeyManagerFactory(Vertx vertx) throws Exception {
        return delegate.getKeyManagerFactory(vertx);
    }

    @Override
    public TrustManagerFactory getTrustManagerFactory(Vertx vertx) throws Exception {

        final TrustManagerFactory trustManagerFactory = delegate.getTrustManagerFactory(vertx);

        final KeyStore keyStore = KeyStoreHelper.create((VertxInternal) vertx, (TrustOptions) delegate).loadStore((VertxInternal) vertx);

        return new SancusTrustManagerFactory(keyStore, trustManagerFactory, callback);
    }

}
