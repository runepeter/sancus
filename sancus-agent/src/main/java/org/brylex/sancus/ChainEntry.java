package org.brylex.sancus;

import org.brylex.sancus.util.Util;

import java.security.KeyStoreException;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.UUID;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 12/04/2017.
 */
public class ChainEntry {

    private X509Certificate certificate;
    private Principal dn;
    private CertificateChain chain;
    private ChainEntry issuer;
    private String resolvedBy = "DEFAULT";
    private String trustedBy = "NOT";
    ChainEntry(X509Certificate certificate, CertificateChain chain) {
        this.chain = chain;
        this.certificate = certificate;
        this.dn = certificate.getSubjectDN();
        if (!certificate.getSubjectDN().equals(certificate.getIssuerDN())) {
            this.issuer = new ChainEntry(certificate.getIssuerDN(), chain);
        }

        this.resolvedBy = "SERVER";
    }

    ChainEntry(Principal principal, CertificateChain chain) {
        this.chain = chain;
        this.dn = principal;
        this.resolvedBy = "MISSING";
    }

    public X509Certificate certificate() {
        return certificate;
    }

    public Principal dn() {
        return dn;
    }

    public ChainEntry issuedBy(X509Certificate issuer) {
        this.issuer = new ChainEntry(issuer, this.chain);
        return this.issuer;
    }

    public ChainEntry issuedBy(Principal issuerDN) {
        this.issuer = new ChainEntry(issuerDN, this.chain);
        return this.issuer;
    }

    public ChainEntry issuedBy() {
        return issuer;
    }

    public String resolvedBy() {
        return resolvedBy;
    }

    public String resolvedBy(String resolverId) {
        this.resolvedBy = resolverId;
        return resolvedBy;
    }

    public String trustedBy() {
        return trustedBy;
    }

    public String trustedBy(String resolverId) {
        this.trustedBy = resolverId;
        return resolverId;
    }

    public ChainEntry apply(X509Certificate certificate, String resolverId) {
        this.certificate = certificate;
        this.resolvedBy = resolverId;

        if (Util.equals(certificate.getSubjectDN(), certificate.getIssuerDN())) {
            this.chain.last(this);
        } else {
            issuedBy(certificate.getIssuerDN());
        }

        try {
            chain.jks().setCertificateEntry(resolverId + "_" + UUID.randomUUID().toString(), certificate);
        } catch (KeyStoreException e) {
            throw new RuntimeException("Unable to apply certificate to KeyStore.", e);
        }

        return this;
    }

    public void visit(Visitor visitor) {
        visitor.visit(this);
    }

    @Override
    public String toString() {

        StringBuffer buffer = new StringBuffer();

        buffer.append("[").append(resolvedBy).append("][").append(trustedBy).append("] ").append(dn());

        return buffer.toString();
    }

    public interface Visitor {
        void visit(ChainEntry entry);
    }
}
