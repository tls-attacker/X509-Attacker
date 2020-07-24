package de.rub.nds.signatureengine;

import de.rub.nds.signatureengine.keyparsers.DefaultKeyParser;
import de.rub.nds.signatureengine.keyparsers.KeyType;

public class DsaWithSha224SignatureEngine extends JavaSignatureEngine {

    public static final String objectIdentifierString = "2.16.840.1.101.3.4.3.1";

    private static final String signatureAlgorithm = "SHA224withDSA";
    
    public static final String name = "DSAwithSHA224";
    
    public static final KeyType keyType = KeyType.DSA;

    public DsaWithSha224SignatureEngine() throws SignatureEngineException {
        super(signatureAlgorithm, new DefaultKeyParser());
    }
}
