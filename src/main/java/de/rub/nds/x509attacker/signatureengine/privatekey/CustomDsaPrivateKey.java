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
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;

public class CustomDsaPrivateKey extends CustomPrivateKey implements DSAPrivateKey {

    private final BigInteger privateKey;

    public CustomDsaPrivateKey(BigInteger privateKey) {
        this.privateKey = privateKey;
    }

    @Override
    public String getAlgorithm() {
        return "DSA";
    }

    @Override
    public BigInteger getX() {
        return privateKey;
    }

    @Override
    public DSAParams getParams() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

}
