package de.rub.nds.signatureengine;

import de.rub.nds.signatureengine.JavaSignatureEngine;
import de.rub.nds.signatureengine.SignatureEngineException;
import de.rub.nds.signatureengine.keyparsers.DefaultKeyParser;
import de.rub.nds.signatureengine.keyparsers.KeyType;

public class EcdsaWithSha384SignatureEngine extends JavaSignatureEngine {

    public static final String objectIdentifierString = "1.2.840.10045.4.3.3";

    private static final String signatureAlgorithm = "SHA384withECDSA";
    
    public static final String name = "ECDSAwithSHA384";
    
    public static final KeyType keyType = KeyType.ECDSA;

    public EcdsaWithSha384SignatureEngine() throws SignatureEngineException {
        super(signatureAlgorithm, new DefaultKeyParser());
    }
}
