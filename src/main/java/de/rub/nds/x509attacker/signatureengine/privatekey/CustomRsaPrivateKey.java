/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.signatureengine.privatekey;

import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;

public class CustomRsaPrivateKey extends CustomPrivateKey implements RSAPrivateKey {

    private final BigInteger modulus;
    private final BigInteger privateExponent;

    public CustomRsaPrivateKey(BigInteger modulus, BigInteger privateExponent) {
        this.modulus = modulus;
        this.privateExponent = privateExponent;
    }

    @Override
    public String getAlgorithm() {
        return "RSA";
    }

    @Override
    public BigInteger getPrivateExponent() {
        return privateExponent;
    }

    @Override
    public BigInteger getModulus() {
        return modulus;
    }
}
