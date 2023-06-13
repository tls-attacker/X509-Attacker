/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.chooser;

import de.rub.nds.protocol.crypto.ec.Point;
import de.rub.nds.protocol.xml.Pair;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.constants.X509NamedCurve;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import de.rub.nds.x509attacker.context.X509Context;
import java.math.BigInteger;
import java.util.List;

public class X509Chooser {

    private final X509CertificateConfig config;

    private final X509Context context;

    public X509Chooser(X509CertificateConfig config, X509Context context) {
        this.config = config;
        this.context = context;
    }

    public X509CertificateConfig getConfig() {
        return config;
    }

    public X509Context getContext() {
        return context;
    }

    public X509SignatureAlgorithm getSignatureAlgorithm() {
        if (context.getSubjectSignatureAlgorithm() != null) {
            return context.getSubjectSignatureAlgorithm();
        } else {
            return config.getDefaultSignatureAlgorithm();
        }
    }

    public X509PublicKeyType getIssuerPublicKeyType() {
        if (context.getIssuerPublicKeyType() != null) {
            return context.getIssuerPublicKeyType();
        } else {
            return config.getDefaultIssuerPublicKeyType();
        }
    }

    public BigInteger getIssuerRsaPrivateKey() {
        if (context.getIssuerRsaPrivateKey() != null) {
            return context.getIssuerRsaPrivateKey();
        } else {
            return config.getDefaultIssuerRsaPrivateKey();
        }
    }

    public BigInteger getIssuerRsaModulus() {
        if (context.getIssuerRsaModulus() != null) {
            return context.getIssuerRsaModulus();
        } else {
            return config.getDefaultIssuerRsaModulus();
        }
    }

    public BigInteger getIssuerDsaPrivateKey() {
        if (context.getIssuerDsaPrivateKey() != null) {
            return context.getIssuerDsaPrivateKey();
        } else {
            return config.getDefaultIssuerDsaPrivateKey();
        }
    }

    public BigInteger getIssuerEcPrivateKey() {
        if (context.getIssuerEcPrivateKey() != null) {
            return context.getIssuerEcPrivateKey();
        } else {
            return config.getDefaultIssuerEcPrivateKey();
        }
    }

    public List<Pair<X500AttributeType, String>> getIssuer() {
        if (context.getIssuer() != null) {
            return context.getIssuer();
        } else {
            return config.getDefaultIssuer();
        }
    }

    public byte[] getIssuerUniqueId() {
        if (context.getIssuerUniqueId() != null) {
            return context.getIssuerUniqueId();
        } else {
            return config.getDefaultIssuerUniqueId();
        }
    }

    public X509PublicKeyType getSubjectPublicKeyType() {
        if (context.getSubjectPublicKeyType() != null) {
            return context.getSubjectPublicKeyType();
        } else {
            return config.getPublicKeyType();
        }
    }

    public X509NamedCurve getSubjectNamedCurve() {
        if (context.getSubjectNamedCurve() != null) {
            return context.getSubjectNamedCurve();
        } else {
            return config.getDefaultSubjectNamedCurve();
        }
    }

    public BigInteger getSubjectDhPrivateKey() {
        if (context.getSubjectDhPrivateKey() != null) {
            return context.getSubjectDhPrivateKey();
        } else {
            return config.getDhPrivateKey();
        }
    }

    public BigInteger getSubjectDhModulus() {
        if (context.getSubjectDhModulus() != null) {
            return context.getSubjectDhModulus();
        } else {
            return config.getDhModulus();
        }
    }

    public BigInteger getSubjectDhGenerator() {
        if (context.getSubjectDhModulus() != null) {
            return context.getSubjectDhGenerator();
        } else {
            return config.getDhGenerator();
        }
    }

    public BigInteger getSubjectRsaPublicExponent() {
        if (context.getSubjectRsaPublicExponent() != null) {
            return context.getSubjectRsaPublicExponent();
        } else {
            return config.getRsaPublicExponent();
        }
    }

    public BigInteger getSubjectRsaModulus() {
        if (context.getSubjectRsaModulus() != null) {
            return context.getSubjectRsaModulus();
        } else {
            return config.getRsaModulus();
        }
    }

    public BigInteger getSubjectEcPrivateKey() {
        if (context.getSubjectEcPrivateKey() != null) {
            return context.getSubjectEcPrivateKey();
        } else {
            return config.getEcPrivateKey();
        }
    }

    public Point getSubjectEcPublicKey() {
        if (context.getSubjectEcPublicKey() != null) {
            return context.getSubjectEcPublicKey();
        } else {
            return config.getEcPublicKey();
        }
    }

    public BigInteger getSubjectDsaPrivateKey() {
        if (context.getSubjectDsaPrivateKey() != null) {
            return context.getSubjectDsaPrivateKey();
        } else {
            return config.getDsaPrivateKey();
        }
    }

    public BigInteger getSubjectRsaPrivateKey() {
        if (context.getSubjectRsaPrivateKey() != null) {
            return context.getSubjectRsaPrivateKey();
        } else {
            return config.getRsaPrivateKey();
        }
    }

    public BigInteger getSubjectDhPublicKey() {
        if (context.getSubjectDhPublicKey() != null) {
            return context.getSubjectDhPublicKey();
        } else {
            return config.getDhPublicKey();
        }
    }
}
