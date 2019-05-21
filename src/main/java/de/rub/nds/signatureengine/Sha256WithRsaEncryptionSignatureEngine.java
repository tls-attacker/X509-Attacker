package de.rub.nds.signatureengine;

import de.rub.nds.signatureengine.keyparsers.DefaultKeyParser;

public class Sha256WithRsaEncryptionSignatureEngine extends JavaSignatureEngine {

    public static final String objectIdentifierString = "1.2.840.113549.1.1.11";

    public Sha256WithRsaEncryptionSignatureEngine() throws SignatureEngineException {
        super(objectIdentifierString, new DefaultKeyParser());
    }
}
