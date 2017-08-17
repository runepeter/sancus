package org.brylex.sancus;

import com.google.common.collect.Lists;
import org.brylex.sancus.resolver.HandshakeResolver;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import static com.google.common.base.Preconditions.checkArgument;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 12/04/2017.
 */
public class CertificateChain {

    private final KeyStore jks;
    private ChainEntry head;
    private ChainEntry last;

    private CertificateChain(KeyStore jks) {
        this.jks = jks;
    }

    private CertificateChain(X509Certificate... certificate) {
        apply(certificate);
        try {
            this.jks = KeyStore.getInstance("JKS");
            this.jks.load(null);
        } catch (Exception e) {
            throw new RuntimeException("Unable to initialize create JKS.", e);
        }
    }

    public static CertificateChain create(KeyStore jks) {

        applyDummyCertIfEmptyJks(jks);

        return new CertificateChain(jks);
    }

    private static void applyDummyCertIfEmptyJks(KeyStore jks) {
        try {
            if (jks.size() == 0) {

                KeyStore dummy = KeyStore.getInstance("JKS");
                try (InputStream is = HandshakeResolver.class.getResourceAsStream("/dummy.jks")) {
                    dummy.load(is, "changeit".toCharArray());
                }

                java.security.cert.Certificate dummyCertificate = dummy.getCertificate("sancus-dummy");

                jks.setCertificateEntry("dummy-sancus", dummyCertificate);
            }
        } catch (Exception e) {
            throw new RuntimeException("Unable to generate and apply dummy certificate to empty KeyStore.", e);
        }
    }

    public CertificateChain apply(X509Certificate... chain) {

        checkArgument(chain != null);
        checkArgument(chain.length > 0);

        List<X509Certificate> list = Arrays.asList(chain);
        Collections.sort(list, new ChainComparator());

        Iterator<X509Certificate> iterator = list.iterator();

        this.head = new ChainEntry(iterator.next(), this);

        ChainEntry entry = this.head;
        while (iterator.hasNext()) {
            X509Certificate next = iterator.next();
            entry = entry.issuedBy(next);
        }

        this.last = entry;

        return this;
    }

    public static CertificateChain create(X509Certificate... chain) {

        CertificateChain c = new CertificateChain(chain);

        return c;
    }

    public ChainEntry issuedBy() {
        return head.issuedBy();
    }

    public KeyStore jks() {
        return jks;
    }

    public boolean isComplete() {

        // TODO rpbjo: This one does not need to be resolved each time.
        List<X509Certificate> list = toList();
        X509Certificate last = list.get(list.size() - 1);

        return last.getSubjectDN().equals(last.getIssuerDN());
    }

    public List<X509Certificate> toList() {

        final List<X509Certificate> list = Lists.newArrayList();

        ChainEntry entry = head;
        while (entry != null) {

            if (entry.certificate() != null) {
                list.add(entry.certificate());
            }

            entry = entry.issuedBy();
        }

        return list;
    }

    public ChainEntry last(ChainEntry entry) {
        this.last = entry;
        return entry;
    }

    public ChainEntry last() {
        return last;
    }

    @Override
    public String toString() {

        StringBuffer buffer = new StringBuffer();

        ChainEntry entry = head;
        while (entry != null) {

            buffer.append(entry.toString()).append('\n');

            entry = entry.issuedBy();
        }

        return buffer.toString();
    }

    public ChainEntry head() {
        return head;
    }

    public void visit(ChainEntry.Visitor visitor) {
        ChainEntry entry = head;
        while (entry != null) {

            entry.visit(visitor);

            entry = entry.issuedBy();
        }
    }

    public interface Callback {
        void onCertificateChain(CertificateChain chain);
    }

    public interface Resolver {

        CertificateChain resolve(CertificateChain chain);

    }

    public interface Truster {

        CertificateChain check(CertificateChain chain);

    }

}
