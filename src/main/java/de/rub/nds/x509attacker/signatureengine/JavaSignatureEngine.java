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
import java.security.*;

public abstract class JavaSignatureEngine extends SignatureEngine {

    private final String javaName;

    /**
     * @param signatureAlgorithm
     * @param javaName
     */
    public JavaSignatureEngine(X509SignatureAlgorithm signatureAlgorithm, final String javaName) {
        super(signatureAlgorithm);
        this.javaName = javaName;
    }

    /**
     * Signs the given data and returns the signature value. Cannot be called before the signature
     * engine is initialized.
     *
     * @param toBeSigned The data to be signed.
     * @return The signature value.
     */
    @Override
    public byte[] sign(final PrivateKey privateKey, final byte[] toBeSigned)
            throws SignatureEngineException {
        try {
            Signature signatureObj = Signature.getInstance(javaName);
            signatureObj.initSign(privateKey);
            signatureObj.update(toBeSigned);
            return signatureObj.sign();
        } catch (InvalidKeyException | SignatureException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
