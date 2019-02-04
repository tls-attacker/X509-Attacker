package de.rub.nds.x509attacker.signatureengine;

import de.rub.nds.x509attacker.signatureengine.keyparsers.RsaPkcs1KeyParser;

public class Md4WithRsaEncryptionSignatureEngine extends JavaSignatureEngine {

    public static final String objectIdentifierString = "1.2.840.113549.1.1.1.3";

    private static final String signatureAlgorithm = "MD4withRSAEncryption";

    public Md4WithRsaEncryptionSignatureEngine() throws SignatureEngineException {
        super(signatureAlgorithm, new RsaPkcs1KeyParser());
    }
}