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

    public X509NamedCurve getIssuerNamedCurve() {
        if (context.getIssuerNamedCurve() != null) {
            return context.getIssuerNamedCurve();
        } else {
            return config.getDefaultIssuerNamedCurve();
        }
    }

    public BigInteger getIssuerRsaPrivateExponent() {
        if (context.getIssuerRsaPrivateExponent() != null) {
            return context.getIssuerRsaPrivateExponent();
        } else {
            return config.getDefaultIssuerRsaPrivateExponent();
        }
    }

    public BigInteger getIssuerRsaModulus() {
        if (context.getIssuerRsaModulus() != null) {
            return context.getIssuerRsaModulus();
        } else {
            return config.getDefaultIssuerRsaModulus();
        }
    }

    public BigInteger getIssuerDsaPrivateKeyX() {
        if (context.getIssuerDsaPrivateKeyX() != null) {
            return context.getIssuerDsaPrivateKeyX();
        } else {
            return config.getDefaultIssuerDsaPrivateKey();
        }
    }

    public BigInteger getIssuerDsaPrivateK() {
        if (context.getIssuerDsaPrivateK() != null) {
            return context.getIssuerDsaPrivateK();
        } else {
            return config.getDefaultIssuerDsaNonce();
        }
    }

    public BigInteger getIssuerEcPrivateKey() {
        if (context.getIssuerEcPrivateKey() != null) {
            return context.getIssuerEcPrivateKey();
        } else {
            return config.getDefaultIssuerEcPrivateKey();
        }
    }

    public Point getIssuerEcPublicKey() {
        if (context.getIssuerEcPrivateKey() != null) {
            return context.getIssuerEcPublicKey();
        } else {
            return config.getDefaultIssuerEcPublicKey();
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
            return config.getDefaultSubjectRsaModulus();
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
            return config.getDefaultSubjectDsaPrivateKey();
        }
    }

    public BigInteger getSubjectDsaPrivateKeyK() {
        if (context.getSubjectDsaPrivateK() != null) {
            return context.getSubjectDsaPrivateK();
        } else {
            return config.getDefaultSubjectDsaNonce();
        }
    }

    public BigInteger getSubjectRsaPrivateKey() {
        if (context.getSubjectRsaPrivateExponent() != null) {
            return context.getSubjectRsaPrivateExponent();
        } else {
            return config.getDefaultSubjectRsaPrivateExponent();
        }
    }

    public BigInteger getSubjectDhPublicKey() {
        if (context.getSubjectDhPublicKey() != null) {
            return context.getSubjectDhPublicKey();
        } else {
            return config.getDefaultSubjectDhPublicKey();
        }
    }

    public BigInteger getSubjectDsaPrimeP() {
        if (context.getSubjectDsaPrimeModulusP() != null) {
            return context.getSubjectDsaPrimeModulusP();
        } else {
            return config.getDefaultSubjectDsaPrimeP();
        }
    }

    public BigInteger getSubjectDsaPrimeQ() {
        if (context.getSubjectDsaPrimeDivisorQ() != null) {
            return context.getSubjectDsaPrimeDivisorQ();
        } else {
            return config.getDefaultSubjectDsaPrimeQ();
        }
    }

    public BigInteger getSubjectDsaGenerator() {
        if (context.getSubjectDsaGeneratorG() != null) {
            return context.getSubjectDsaGeneratorG();
        } else {
            return config.getDefaultSubjectDsaGenerator();
        }
    }

    public BigInteger getIssuerDsaPrimeP() {
        if (context.getIssuerDsaPrimeModulusP() != null) {
            return context.getIssuerDsaPrimeModulusP();
        } else {
            return config.getDefaultIssuerDsaPrimeP();
        }
    }

    public BigInteger getIssuerDsaPrimeQ() {
        if (context.getIssuerDsaPrimeDivisorQ() != null) {
            return context.getIssuerDsaPrimeDivisorQ();
        } else {
            return config.getDefaultIssuerDsaPrimeQ();
        }
    }

    public BigInteger getIssuerDsaGenerator() {
        if (context.getIssuerDsaGeneratorG() != null) {
            return context.getIssuerDsaGeneratorG();
        } else {
            return config.getDefaultIssuerDsaGenerator();
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
}
