package de.rub.nds.signatureengine;

import de.rub.nds.signatureengine.keyparsers.DefaultKeyParser;
import de.rub.nds.signatureengine.keyparsers.KeyType;

public class Sha512WithRsaEncryptionSignatureEngine extends JavaSignatureEngine {

    public static final String objectIdentifierString = "1.2.840.113549.1.1.13";
    
    private static final String signatureAlgorithm = "SHA512withRSA";
    
    public static final String name = "SHA512withRSA";
    
    public static final KeyType keyType = KeyType.RSA;

    public Sha512WithRsaEncryptionSignatureEngine() throws SignatureEngineException {
        super(signatureAlgorithm, new DefaultKeyParser());
    }
}
