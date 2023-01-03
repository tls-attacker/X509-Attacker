/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.context;

import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import org.apache.commons.lang3.tuple.Pair;

public class X509Context {

    private BigInteger issuerRsaPrivateKey = null;

    private BigInteger issuerRsaModulus = null;

    private BigInteger issuerDsaPublicKeyY = null;

    private BigInteger issuerDsaPrivateKey = null;

    private BigInteger issuerEcPrivateKey = null;

    private X509PublicKeyType issuerPublicKeyType = null;

    private X509SignatureAlgorithm signatureAlgorithm;

    private List<Pair<X500AttributeType, String>> issuer = null;

    private byte[] issuerUniqueId = null;

    public X509Context() {}

    public BigInteger getIssuerDsaPublicKeyY() {
        return issuerDsaPublicKeyY;
    }

    public void setIssuerDsaPublicKeyY(BigInteger issuerDsaPublicKeyY) {
        this.issuerDsaPublicKeyY = issuerDsaPublicKeyY;
    }

    public X509SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(X509SignatureAlgorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public BigInteger getIssuerRsaPrivateKey() {
        return issuerRsaPrivateKey;
    }

    public void setIssuerRsaPrivateKey(BigInteger issuerRsaPrivateKey) {
        this.issuerRsaPrivateKey = issuerRsaPrivateKey;
    }

    public BigInteger getIssuerRsaModulus() {
        return issuerRsaModulus;
    }

    public void setIssuerRsaModulus(BigInteger issuerRsaModulus) {
        this.issuerRsaModulus = issuerRsaModulus;
    }

    public BigInteger getIssuerDsaPrivateKey() {
        return issuerDsaPrivateKey;
    }

    public void setIssuerDsaPrivateKey(BigInteger issuerDsaPrivateKey) {
        this.issuerDsaPrivateKey = issuerDsaPrivateKey;
    }

    public BigInteger getIssuerEcPrivateKey() {
        return issuerEcPrivateKey;
    }

    public void setIssuerEcPrivateKey(BigInteger issuerEcPrivateKey) {
        this.issuerEcPrivateKey = issuerEcPrivateKey;
    }

    public List<Pair<X500AttributeType, String>> getIssuer() {
        return issuer;
    }

    public void setIssuer(List<Pair<X500AttributeType, String>> issuer) {
        this.issuer = issuer;
    }

    public byte[] getIssuerUniqueId() {
        if (issuerUniqueId != null) {
            return Arrays.copyOf(issuerUniqueId, issuerUniqueId.length);
        } else {
            return null;
        }
    }

    public void setIssuerUniqueId(byte[] issuerUniqueId) {
        this.issuerUniqueId = Arrays.copyOf(issuerUniqueId, issuerUniqueId.length);
    }

    public X509PublicKeyType getIssuerPublicKeyType() {
        return issuerPublicKeyType;
    }

    public void setIssuerPublicKeyType(X509PublicKeyType issuerPublicKeyType) {
        this.issuerPublicKeyType = issuerPublicKeyType;
    }
}
