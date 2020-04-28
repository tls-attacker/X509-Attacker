package de.rub.nds.signatureengine.keyparsers;

import de.rub.nds.signatureengine.JavaSignatureEngine;
import de.rub.nds.signatureengine.SignatureEngineException;

public class Sha1WithEcdsaSignatureEngine extends JavaSignatureEngine {

    public static final String objectIdentifierString = "1.2.840.10045.4.1";

    private static final String signatureAlgorithm = "SHA1withECDSA";
    
    public static final String name = "SHA1withECDSA";
    
    public static final KeyType keyType = KeyType.ECDSA;

    public Sha1WithEcdsaSignatureEngine() throws SignatureEngineException {
        super(signatureAlgorithm, new DefaultKeyParser());
    }
}
