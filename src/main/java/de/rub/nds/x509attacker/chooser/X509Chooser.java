/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.chooser;

import de.rub.nds.protocol.constants.HashAlgorithm;
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
            return config.getRsaModulus();
        }
    }

    public BigInteger getIssuerDsaPrivateKeyX() {
        if (context.getIssuerDsaPrivateKeyX() != null) {
            return context.getIssuerDsaPrivateKeyX();
        } else {
            return config.getDefaultIssuerDsaPrivateKeyX();
        }
    }

    public BigInteger getIssuerDsaPrivateK() {
        if (context.getIssuerDsaPrivateK() != null) {
            return context.getIssuerDsaPrivateK();
        } else {
            return config.getDefaultIssuerDsaPrivateK();
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
            return config.getDefaultNamedCurve();
        }
    }

    public BigInteger getSubjectDhPrivateKey() {
        if (context.getSubjectDhPrivateKey() != null) {
            return context.getSubjectDhPrivateKey();
        } else {
            return config.getDefaultSubjectDhPrivateKey();
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
            return config.getDefaultSubjectRsaPublicExponent();
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
            return config.getDefaultSubjectEcPrivateKey();
        }
    }

    public Point getSubjectEcPublicKey() {
        if (context.getSubjectEcPublicKey() != null) {
            return context.getSubjectEcPublicKey();
        } else {
            return config.getDefaultSubjectEcPublicKey();
        }
    }

    public BigInteger getSubjectDsaPrivateKeyX() {
        if (context.getSubjectDsaPrivateKeyX() != null) {
            return context.getSubjectDsaPrivateKeyX();
        } else {
            return config.getDefaultSubjectDsaPrivateKeyX();
        }
    }

    public BigInteger getSubjectDsaPrivateKeyK() {
        if (context.getSubjectDsaPrivateK() != null) {
            return context.getSubjectDsaPrivateK();
        } else {
            return config.getDefaultSubjectDsaPrivateK();
        }
    }

    public BigInteger getSubjectRsaPrivateKey() {
        if (context.getSubjectRsaPrivateKey() != null) {
            return context.getSubjectRsaPrivateKey();
        } else {
            return config.getDefaultSubjectRsaPrivateKey();
        }
    }

    public BigInteger getSubjectDhPublicKey() {
        if (context.getSubjectDhPublicKey() != null) {
            return context.getSubjectDhPublicKey();
        } else {
            return config.getDefaultSubjectDhPublicKey();
        }
    }

    public BigInteger getDsaPrimeP() {
        if (context.getSubjectDsaPrimeModulusP() != null) {
            return context.getSubjectDsaPrimeModulusP();
        } else {
            return config.getDsaPrimeP();
        }
    }

    public BigInteger getDsaPrimeQ() {
        if (context.getSubjectDsaPrimeDivisorQ() != null) {
            return context.getSubjectDsaPrimeDivisorQ();
        } else {
            return config.getDsaPrimeQ();
        }
    }

    public BigInteger getDsaGenerator() {
        if (context.getSubjectDsaGeneratorG() != null) {
            return context.getSubjectDsaGeneratorG();
        } else {
            return config.getDsaGenerator();
        }
    }

    public byte[] getRsaPssSalt() {
        if (context.getRsaPssSalt() != null) {
            return context.getRsaPssSalt();
        } else {
            return config.getRsaPssSalt();
        }
    }

    public HashAlgorithm getRsaPssHashAlgorithm() {
        if (context.getRsaPssHashAlgorithm() != null) {
            return context.getRsaPssHashAlgorithm();
        } else {
            return config.getRsaPssHashAlgorithm();
        }
    }

    public BigInteger getEcdsaNonce() {
        if (context.getEcdsaNonce() != null) {
            return context.getEcdsaNonce();
        } else {
            return config.getDefaultEcPrivateKeyK();
        }
    }
}
