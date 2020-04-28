package de.rub.nds.signatureengine;

import de.rub.nds.signatureengine.keyparsers.DefaultKeyParser;
import de.rub.nds.signatureengine.keyparsers.KeyType;

public class DsaWithSha1SignatureEngine extends JavaSignatureEngine {

    public static final String objectIdentifierString = "1.2.840.10040.4.3";

    private static final String signatureAlgorithm = "DSAwithSHA1";
    
    public static final String name = "DSAwithSHA1";
    
    public static final KeyType keyType = KeyType.DSA;

    public DsaWithSha1SignatureEngine() throws SignatureEngineException {
        super(signatureAlgorithm, new DefaultKeyParser());
    }
}
