package de.rub.nds.signatureengine;

import de.rub.nds.signatureengine.JavaSignatureEngine;
import de.rub.nds.signatureengine.SignatureEngineException;
import de.rub.nds.signatureengine.keyparsers.DefaultKeyParser;
import de.rub.nds.signatureengine.keyparsers.KeyType;

public class EcdsaWithSha512SignatureEngine extends JavaSignatureEngine {

    public static final String objectIdentifierString = "1.2.840.10045.4.3.4";

    private static final String signatureAlgorithm = "SHA512withECDSA";
    
    public static final String name = "ECDSAwithSHA512";
    
    public static final KeyType keyType = KeyType.ECDSA;

    public EcdsaWithSha512SignatureEngine() throws SignatureEngineException {
        super(signatureAlgorithm, new DefaultKeyParser());
    }
}
