package de.rub.nds.signatureengine;

import de.rub.nds.signatureengine.keyparsers.DefaultKeyParser;
import de.rub.nds.signatureengine.keyparsers.KeyType;

public class Sha256WithRsaEncryptionSignatureEngine extends JavaSignatureEngine {

    public static final String objectIdentifierString = "1.2.840.113549.1.1.11";
    
    private static final String signatureAlgorithm = "SHA256withRSA";
    
    public static final String name = "SHA256withRSA";
    
    public static final KeyType keyType = KeyType.RSA;

    public Sha256WithRsaEncryptionSignatureEngine() throws SignatureEngineException {
        super(signatureAlgorithm, new DefaultKeyParser());
    }
}
