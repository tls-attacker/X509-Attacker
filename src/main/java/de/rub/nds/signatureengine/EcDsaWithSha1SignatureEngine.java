package de.rub.nds.signatureengine;

import de.rub.nds.signatureengine.keyparsers.DefaultKeyParser;

public class EcDsaWithSha1SignatureEngine extends JavaSignatureEngine {

    public static final String objectIdentifierString = "1.2.840.10045.4.1";

    public EcDsaWithSha1SignatureEngine() throws SignatureEngineException {
        super(objectIdentifierString, new DefaultKeyParser());
    }
}
