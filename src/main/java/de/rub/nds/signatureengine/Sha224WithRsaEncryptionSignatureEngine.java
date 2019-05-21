package de.rub.nds.signatureengine;

import de.rub.nds.signatureengine.keyparsers.DefaultKeyParser;

public class Sha224WithRsaEncryptionSignatureEngine extends JavaSignatureEngine {

    public static final String objectIdentifierString = "1.2.840.113549.1.1.14";

    public Sha224WithRsaEncryptionSignatureEngine() throws SignatureEngineException {
        super(objectIdentifierString, new DefaultKeyParser());
    }
}
