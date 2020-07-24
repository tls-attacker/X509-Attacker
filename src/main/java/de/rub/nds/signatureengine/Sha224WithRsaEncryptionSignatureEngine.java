package de.rub.nds.signatureengine;

import de.rub.nds.signatureengine.keyparsers.DefaultKeyParser;
import de.rub.nds.signatureengine.keyparsers.KeyType;

public class Sha224WithRsaEncryptionSignatureEngine extends JavaSignatureEngine {

    public static final String objectIdentifierString = "1.2.840.113549.1.1.14";
    
    private static final String signatureAlgorithm = "SHA224withRSA";
    
    public static final String name = "SHA224withRSA";
    
    public static final KeyType keyType = KeyType.RSA;

    public Sha224WithRsaEncryptionSignatureEngine() throws SignatureEngineException {
        super(signatureAlgorithm, new DefaultKeyParser());
    }
}
