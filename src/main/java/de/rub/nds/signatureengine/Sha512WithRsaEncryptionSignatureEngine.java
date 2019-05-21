package de.rub.nds.signatureengine;

import de.rub.nds.signatureengine.keyparsers.DefaultKeyParser;

public class Sha512WithRsaEncryptionSignatureEngine extends JavaSignatureEngine {

    public static final String objectIdentifierString = "1.2.840.113549.1.1.13";

    public Sha512WithRsaEncryptionSignatureEngine() throws SignatureEngineException {
        super(objectIdentifierString, new DefaultKeyParser());
    }
}
