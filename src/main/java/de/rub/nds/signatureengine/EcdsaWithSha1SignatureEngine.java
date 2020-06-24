package de.rub.nds.signatureengine;

import de.rub.nds.signatureengine.JavaSignatureEngine;
import de.rub.nds.signatureengine.SignatureEngineException;
import de.rub.nds.signatureengine.keyparsers.DefaultKeyParser;
import de.rub.nds.signatureengine.keyparsers.KeyType;

public class EcdsaWithSha1SignatureEngine extends JavaSignatureEngine {

    public static final String objectIdentifierString = "1.2.840.10045.4.1";

    private static final String signatureAlgorithm = "SHA1withECDSA"; //Java Signature bennenung
    
    public static final String name = "ECDSAwithSHA1";
    
    public static final KeyType keyType = KeyType.ECDSA;

    public EcdsaWithSha1SignatureEngine() throws SignatureEngineException {
        super(signatureAlgorithm, new DefaultKeyParser());
    }
}
