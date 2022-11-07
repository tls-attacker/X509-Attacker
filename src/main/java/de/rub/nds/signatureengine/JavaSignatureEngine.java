/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.signatureengine;

import de.rub.nds.signatureengine.keyparsers.KeyParser;
import de.rub.nds.signatureengine.keyparsers.KeyParserException;
import java.security.*;

public abstract class JavaSignatureEngine extends SignatureEngine {

    private KeyParser keyParser;
    private final String signatureAlgorithm;
    private PrivateKey privateKey = null;

    private boolean isInitialized = false;

    public JavaSignatureEngine(final String signatureAlgorithm, final KeyParser keyParser)
            throws SignatureEngineException {
        if (keyParser == null) {
            throw new SignatureEngineException("No key parser specified!");
        }
        this.keyParser = keyParser;
        this.signatureAlgorithm = signatureAlgorithm;
    }

    // Todo: Handle parameters argument.
    /**
     * Initializes the signature engine with the corresponding key material.
     *
     * @param keyBytes Bytes of the key material.
     * @param keyFormat Indicates how the key bytes shall be parsed. Supported
     * key types: PEM_ENCODED.
     * @param parameters Binary ASN.1 data from AlgorithmIdentifier's parameter
     * field (see RFC 5280 4.1.1.2).
     */
    @Override
    public void init(final byte[] keyBytes, final SignatureEngine.KeyFormat keyFormat, final byte[] parameters)
            throws SignatureEngineException {
        try {
            this.privateKey = this.keyParser.parse(keyBytes, keyFormat);
            this.isInitialized = true;
        } catch (KeyParserException e) {
            throw new SignatureEngineException(e);
        }
    }

    /**
     * Signs the given data and returns the signature value. Cannot be called
     * before the signature engine is initialized.
     *
     * @param toBeSigned The data to be signed.
     * @return The signature value.
     */
    @Override
    public byte[] sign(final byte[] toBeSigned) throws SignatureEngineException {
        byte[] signature = null;
        if (this.isInitialized == false) {
            throw new SignatureEngineException("Signature engine is not initialized!");
        }
        try {
            Signature signatureObj = Signature.getInstance(signatureAlgorithm);
            signatureObj.initSign(this.privateKey);
            signatureObj.update(toBeSigned);
            signature = signatureObj.sign();
        } catch (InvalidKeyException | SignatureException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return signature;
    }
}
