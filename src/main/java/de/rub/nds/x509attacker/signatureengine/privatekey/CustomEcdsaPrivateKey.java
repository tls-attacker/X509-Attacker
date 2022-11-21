/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.signatureengine.privatekey;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;

public class CustomEcdsaPrivateKey extends CustomPrivateKey implements ECPrivateKey {

    private final BigInteger privateKey;

    public CustomEcdsaPrivateKey(BigInteger privateKey) {
        this.privateKey = privateKey;
    }

    @Override
    public String getAlgorithm() {
        return "ECDSA";
    }

    @Override
    public BigInteger getS() {
        return privateKey;
    }

    @Override
    public ECParameterSpec getParams() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

}
