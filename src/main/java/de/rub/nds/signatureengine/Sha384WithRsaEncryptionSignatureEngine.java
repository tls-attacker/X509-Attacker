package de.rub.nds.signatureengine;

import de.rub.nds.signatureengine.keyparsers.DefaultKeyParser;

public class Sha384WithRsaEncryptionSignatureEngine extends JavaSignatureEngine {

    public static final String objectIdentifierString = "1.2.840.113549.1.1.12";

    public Sha384WithRsaEncryptionSignatureEngine() throws SignatureEngineException {
        super(objectIdentifierString, new DefaultKeyParser());
    }
}
