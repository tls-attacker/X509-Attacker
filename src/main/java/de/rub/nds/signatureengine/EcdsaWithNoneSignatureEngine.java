package de.rub.nds.signatureengine;

import de.rub.nds.signatureengine.JavaSignatureEngine;
import de.rub.nds.signatureengine.SignatureEngineException;
import de.rub.nds.signatureengine.keyparsers.DefaultKeyParser;
import de.rub.nds.signatureengine.keyparsers.KeyType;

public class EcdsaWithNoneSignatureEngine extends JavaSignatureEngine {

    public static final String objectIdentifierString = "1.2.840.10045.4.3.2"; //use a SHA256WithECDSA cause there is no oid for nonewithRsa

    private static final String signatureAlgorithm = "NONEWithECDSA";
    
    public static final String name = "NONEWithECDSA";
    
    public static final KeyType keyType = KeyType.ECDSA;

    public EcdsaWithNoneSignatureEngine() throws SignatureEngineException {
        super(signatureAlgorithm, new DefaultKeyParser());
    }
}
