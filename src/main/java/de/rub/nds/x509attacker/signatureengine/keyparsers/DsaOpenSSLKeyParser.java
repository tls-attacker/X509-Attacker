package de.rub.nds.x509attacker.signatureengine.keyparsers;

import sun.security.util.DerInputStream;
import sun.security.util.DerValue;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class DsaOpenSSLKeyParser extends KeyParser {

    public DsaOpenSSLKeyParser() {
        super();
    }

    @Override
    protected PrivateKey parseDerKey(final byte[] keyBytes) throws KeyParserException {
        /* Here, a PKCS#1 key file is expected. Unfortunately, neither Java nor Bouncycastle have native support for
         * parsing PKCS#1 key files. Hence the DER encoded file must be parsed manually.
         */
        // Todo: Test for correct behaviour
        try {
            DerInputStream derInputStream = new DerInputStream(keyBytes);
            DerValue[] sequenceFields = derInputStream.getSequence(0);
            BigInteger p = sequenceFields[1].getBigInteger();
            BigInteger q = sequenceFields[2].getBigInteger();
            BigInteger g = sequenceFields[3].getBigInteger();
            BigInteger x = sequenceFields[5].getBigInteger();
            DSAPrivateKeySpec keySpec = new DSAPrivateKeySpec(x, p, q, g);
            KeyFactory factory = KeyFactory.getInstance("DSA");
            return factory.generatePrivate(keySpec);
        } catch (IOException e) {
            throw new KeyParserException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new KeyParserException(e);
        } catch (InvalidKeySpecException e) {
            throw new KeyParserException(e);
        } catch (IndexOutOfBoundsException e) {
            throw new KeyParserException(e);
        } catch (Exception e) {
            throw new KeyParserException(e);
        }
    }

    @Override
    protected PrivateKey parsePemKey(final byte[] keyBytes) throws KeyParserException {
        try {
            String keyBytesString = new String(keyBytes, "UTF-8");
            keyBytesString = keyBytesString.replace("-----BEGIN DSA PRIVATE KEY-----", "");
            keyBytesString = keyBytesString.replace("-----END DSA PRIVATE KEY-----", "");
            keyBytesString = keyBytesString.replace("\n", "");
            byte[] decodedKeyBytes = Base64.getDecoder().decode(keyBytesString.trim().getBytes());
            return this.parseDerKey(decodedKeyBytes);
        } catch (UnsupportedEncodingException e) {
            throw new KeyParserException(e);
        }
    }
}
