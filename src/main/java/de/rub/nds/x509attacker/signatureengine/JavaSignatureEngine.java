/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.signatureengine;

import de.rub.nds.x509attacker.signatureengine.keyparsers.KeyType;
import java.security.*;

public abstract class JavaSignatureEngine extends SignatureEngine {

    private final String signatureAlgorithm;

    /**
     *
     * @param keyType
     * @param oid
     * @param name
     * @param signatureAlgorithm
     */
    public JavaSignatureEngine(final KeyType keyType, final String oid, final String name,
        final String signatureAlgorithm) {
        super(keyType, oid, name);
        this.signatureAlgorithm = signatureAlgorithm;
    }

    /**
     * Signs the given data and returns the signature value. Cannot be called before the signature engine is
     * initialized.
     *
     * @param  toBeSigned
     *                    The data to be signed.
     * @return            The signature value.
     */
    @Override
    public byte[] sign(final PrivateKey privateKey, final byte[] toBeSigned) throws SignatureEngineException {
        try {
            Signature signatureObj = Signature.getInstance(signatureAlgorithm);
            signatureObj.initSign(privateKey);
            signatureObj.update(toBeSigned);
            return signatureObj.sign();
        } catch (InvalidKeyException | SignatureException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
