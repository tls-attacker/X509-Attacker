package de.rub.nds.signatureengine;

import de.rub.nds.signatureengine.JavaSignatureEngine;
import de.rub.nds.signatureengine.SignatureEngineException;
import de.rub.nds.signatureengine.keyparsers.DefaultKeyParser;
import de.rub.nds.signatureengine.keyparsers.KeyType;

public class EcdsaWithSha256SignatureEngine extends JavaSignatureEngine {

    public static final String objectIdentifierString = "1.2.840.10045.4.3.2";

    private static final String signatureAlgorithm = "SHA256withECDSA";
    
    public static final String name = "ECDSAwithSHA256";
    
    public static final KeyType keyType = KeyType.ECDSA;

    public EcdsaWithSha256SignatureEngine() throws SignatureEngineException {
        super(signatureAlgorithm, new DefaultKeyParser());
    }
}
