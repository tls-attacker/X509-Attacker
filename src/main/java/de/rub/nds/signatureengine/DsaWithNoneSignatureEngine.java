package de.rub.nds.signatureengine;

import de.rub.nds.signatureengine.keyparsers.DefaultKeyParser;
import de.rub.nds.signatureengine.keyparsers.KeyType;

public class DsaWithNoneSignatureEngine extends JavaSignatureEngine {

    public static final String objectIdentifierString = "2.16.840.1.101.3.4.3.2";//use a SHA256WithDSA OID cause there is no oid for nonewithDSA

    private static final String signatureAlgorithm = "NONEwithDSA";
    
    public static final String name = "NONEwithDSA";
    
    public static final KeyType keyType = KeyType.DSA;

    public DsaWithNoneSignatureEngine() throws SignatureEngineException {
        super(signatureAlgorithm, new DefaultKeyParser());
    }
}
