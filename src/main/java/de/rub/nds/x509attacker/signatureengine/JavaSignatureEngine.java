package de.rub.nds.x509attacker.signatureengine;

import de.rub.nds.x509attacker.signatureengine.keyparsers.KeyParser;
import de.rub.nds.x509attacker.signatureengine.keyparsers.KeyParserException;

import java.security.*;

public abstract class JavaSignatureEngine extends SignatureEngine {

    private final Signature signature;

    private KeyParser keyParser;

    private PrivateKey privateKey = null;

    private boolean isInitialized = false;

    public JavaSignatureEngine(final String signatureAlgorithm, final KeyParser keyParser) throws SignatureEngineException {
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

    /**
     * Initializes the signature engine with the corresponding key material.
     *
     * @param keyBytes Bytes of the key material.
     * @param keyType  Indicates how the key bytes shall be parsed. Supported key types: DER_ENCODED, PEM_ENCODED.
     */
    public void init(final byte[] keyBytes, final SignatureEngine.KeyType keyType) throws SignatureEngineException {
        try {
            this.privateKey = this.keyParser.parse(keyBytes, keyType);
            this.isInitialized = true;
        } catch (KeyParserException e) {
            throw new SignatureEngineException(e);
        }
    }

    /**
     * Signs the given data and returns the signature value. Cannot be called before the signature engine is initialized.
     *
     * @param toBeSigned The data to be signed.
     * @return The signature value.
     */
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
