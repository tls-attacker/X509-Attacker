package de.rub.nds.signatureengine;

import de.rub.nds.signatureengine.keyparsers.DefaultKeyParser;
import de.rub.nds.signatureengine.keyparsers.KeyType;

public class DsaWithSha256SignatureEngine extends JavaSignatureEngine {

    public static final String objectIdentifierString = "2.16.840.1.101.3.4.3.2";

    private static final String signatureAlgorithm = "SHA256withDSA";
    
    public static final String name = "DSAwithSHA256";
    
    public static final KeyType keyType = KeyType.DSA;

    public DsaWithSha256SignatureEngine() throws SignatureEngineException {
        super(signatureAlgorithm, new DefaultKeyParser());
    }
}
