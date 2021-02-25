/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.signatureengine;

import de.rub.nds.signatureengine.keyparsers.KeyParser;
import de.rub.nds.signatureengine.keyparsers.KeyParserException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;

public abstract class JavaSignatureEngine extends SignatureEngine {

    private final Signature signature;

    private KeyParser keyParser;

    private PrivateKey privateKey = null;

    private boolean isInitialized = false;

    public JavaSignatureEngine(final String signatureAlgorithm, final KeyParser keyParser)
        throws SignatureEngineException {
        if (keyParser == null) {
            throw new SignatureEngineException("No key parser specified!");
        }
        this.keyParser = keyParser;
        try {
            this.signature = Signature.getInstance(signatureAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new SignatureEngineException(e);
        }
    }

    // Todo: Handle parameters argument.

    /**
     * Initializes the signature engine with the corresponding key material.
     *
     * @param keyBytes
     *                   Bytes of the key material.
     * @param keyType
     *                   Indicates how the key bytes shall be parsed. Supported key types: PEM_ENCODED.
     * @param parameters
     *                   Binary ASN.1 data from AlgorithmIdentifier's parameter field (see RFC 5280 4.1.1.2).
     */
    @Override
    public void init(final byte[] keyBytes, final SignatureEngine.KeyType keyType, final byte[] parameters)
        throws SignatureEngineException {
        try {
            this.privateKey = this.keyParser.parse(keyBytes, keyType);
            this.isInitialized = true;
        } catch (KeyParserException e) {
            throw new SignatureEngineException(e);
        }
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
    public byte[] sign(final byte[] toBeSigned) throws SignatureEngineException {
        byte[] signature = null;
        if (this.isInitialized == false) {
            throw new SignatureEngineException("Signature engine is not initialized!");
        }
        try {
            this.signature.initSign(this.privateKey);
            this.signature.update(toBeSigned);
            signature = this.signature.sign();
        } catch (InvalidKeyException e) {
            throw new SignatureEngineException(e);
        } catch (SignatureException e) {
            throw new SignatureEngineException(e);
        }
        return signature;
    }
}
