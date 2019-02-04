package de.rub.nds.x509attacker.signatureengine;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import java.security.Security;

import static org.junit.Assert.*;

public class Md4WithRsaEncryptionSignatureEngineTest {

    @Test
    public void testInvocation() {
        Security.addProvider(new BouncyCastleProvider());
        SignatureEngine signatureEngine = null;
        try {
            signatureEngine = SignatureEngine.getInstance(Md4WithRsaEncryptionSignatureEngine.objectIdentifierString);
        } catch (SignatureEngineException e) {
            e.printStackTrace();
        }
        assertNotEquals(null, signatureEngine);
    }
}