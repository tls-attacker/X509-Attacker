package de.rub.nds.x509attacker.signatureengine;

import de.rub.nds.x509attacker.signatureengine.keyparsers.RsaPkcs1KeyParser;

public class Md2WithRsaEncryptionSignatureEngine extends JavaSignatureEngine {

    public static final String objectIdentifierString = "1.2.840.113549.1.1.1.2";

    private static final String signatureAlgorithm = "MD2withRSAEncryption";

    public Md2WithRsaEncryptionSignatureEngine() throws SignatureEngineException {
        super(signatureAlgorithm, new RsaPkcs1KeyParser());
    }
}