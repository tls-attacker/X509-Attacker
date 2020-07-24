package de.rub.nds.signatureengine;

import de.rub.nds.signatureengine.keyparsers.DefaultKeyParser;
import de.rub.nds.signatureengine.keyparsers.KeyType;

public class NoneWithRsaEncryptionSignatureEngine extends JavaSignatureEngine {

    public static final String objectIdentifierString = "1.2.840.113549.1.1.11"; //use a SHA256WithRsa cause there is no oid for nonewithRsa
    
    private static final String signatureAlgorithm = "NONEwithRSA";
    
    public static final String name = "NONEwithRSA";
    
    public static final KeyType keyType = KeyType.RSA;

    public NoneWithRsaEncryptionSignatureEngine() throws SignatureEngineException {
        super(signatureAlgorithm, new DefaultKeyParser());
    }
}
