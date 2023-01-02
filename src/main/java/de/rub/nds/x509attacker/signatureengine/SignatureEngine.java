/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.signatureengine;

import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import java.security.PrivateKey;

public abstract class SignatureEngine {

    private final X509SignatureAlgorithm signatureAlgorithm;

    public SignatureEngine(X509SignatureAlgorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    /**
     * Signs the given data and returns the signature value.
     *
     * @param privateKey
     * @param toBeSigned The data to be signed.
     * @return The signature value.
     * @throws de.rub.nds.x509attacker.signatureengine.SignatureEngineException when the signing
     *     fails
     */
    public abstract byte[] sign(PrivateKey privateKey, final byte[] toBeSigned)
            throws SignatureEngineException;

    public X509SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }
}
