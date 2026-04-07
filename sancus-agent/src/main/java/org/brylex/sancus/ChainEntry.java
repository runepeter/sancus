package org.brylex.sancus;

import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.UUID;
import javax.security.auth.x500.X500Principal;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 12/04/2017.
 */
public class ChainEntry {

    private X509Certificate certificate;
    private X500Principal dn;
    private CertificateChain chain;
    private ChainEntry issuer;
    private ResolverSource resolvedBy = ResolverSource.DEFAULT;
    private TrustStatus trustedBy = TrustStatus.UNTRUSTED;

    ChainEntry(X509Certificate certificate, CertificateChain chain) {
        this.chain = chain;
        this.certificate = certificate;
        this.dn = certificate.getSubjectX500Principal();
        if (!certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal())) {
            this.issuer = new ChainEntry(certificate.getIssuerX500Principal(), chain);
        }

        this.resolvedBy = ResolverSource.SERVER;
    }

    ChainEntry(X500Principal principal, CertificateChain chain) {
        this.chain = chain;
        this.dn = principal;
        this.resolvedBy = ResolverSource.MISSING;
    }

    public X509Certificate certificate() {
        return certificate;
    }

    public X500Principal dn() {
        return dn;
    }

    public ChainEntry issuedBy(X509Certificate issuer) {
        this.issuer = new ChainEntry(issuer, this.chain);
        return this.issuer;
    }

    public ChainEntry issuedBy(X500Principal issuerDN) {
        this.issuer = new ChainEntry(issuerDN, this.chain);
        return this.issuer;
    }

    public ChainEntry issuedBy() {
        return issuer;
    }

    public ResolverSource resolvedBy() {
        return resolvedBy;
    }

    public ResolverSource resolvedBy(ResolverSource source) {
        this.resolvedBy = source;
        return resolvedBy;
    }

    public TrustStatus trustedBy() {
        return trustedBy;
    }

    public TrustStatus trustedBy(TrustStatus status) {
        this.trustedBy = status;
        return status;
    }

    public ChainEntry apply(X509Certificate certificate, ResolverSource source) {
        this.certificate = certificate;
        this.resolvedBy = source;

        if (certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal())) {
            this.chain.last(this);
        } else {
            this.chain.last(this);
            issuedBy(certificate.getIssuerX500Principal());
        }

        // TODO hva er dette??
        try {
            chain.jks().setCertificateEntry(source.name() + "_" + UUID.randomUUID().toString(), certificate);
        } catch (KeyStoreException e) {
            throw new RuntimeException("Unable to apply certificate to KeyStore.", e);
        }

        return this;
    }

    public void last(ChainEntry entry) {
        this.chain.last(entry);
    }


    public void visit(Visitor visitor) {
        visitor.visit(this);
    }

    @Override
    public String toString() {

        return "[" + resolvedBy + "][" + trustedBy + "] " + dn();
    }

    public interface Visitor {
        void visit(ChainEntry entry);
    }
}
