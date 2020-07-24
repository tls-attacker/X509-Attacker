package de.rub.nds.signatureengine;

import de.rub.nds.signatureengine.keyparsers.DefaultKeyParser;
import de.rub.nds.signatureengine.keyparsers.KeyType;

public class DsaWithSha512SignatureEngine extends JavaSignatureEngine {

    public static final String objectIdentifierString = "2.16.840.1.101.3.4.3.4";

    private static final String signatureAlgorithm = "SHA512withDSA";
    
    public static final String name = "DSAwithSHA512";
    
    public static final KeyType keyType = KeyType.DSA;

    public DsaWithSha512SignatureEngine() throws SignatureEngineException {
        super(signatureAlgorithm, new DefaultKeyParser());
    }
}
