package de.rub.nds.x509attacker.signatureengine.keyparsers;

import de.rub.nds.x509attacker.signatureengine.SignatureEngineException;
import sun.security.util.DerInputStream;
import sun.security.util.DerValue;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Base64;

public class RsaPkcs1KeyParser extends KeyParser {

    public RsaPkcs1KeyParser() {
        super();
    }

    @Override
    protected PrivateKey parseDerKey(final byte[] keyBytes) throws KeyParserException {
        /* Here, a PKCS#1 key file is expected. Unfortunately, neither Java nor Bouncycastle have native support for
         * parsing PKCS#1 key files. Hence the DER encoded file must be parsed manually.
         */
        try {
            DerInputStream derInputStream = new DerInputStream(keyBytes);
            DerValue[] sequenceFields = derInputStream.getSequence(0);
            BigInteger modulus = sequenceFields[1].getBigInteger();
            BigInteger publicExponent = sequenceFields[2].getBigInteger();
            BigInteger privateExponent = sequenceFields[3].getBigInteger();
            BigInteger primeP = sequenceFields[4].getBigInteger();
            BigInteger primeQ = sequenceFields[5].getBigInteger();
            BigInteger exponent1 = sequenceFields[6].getBigInteger();
            BigInteger exponent2 = sequenceFields[7].getBigInteger();
            BigInteger coefficientCrt = sequenceFields[8].getBigInteger();
            RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(modulus, publicExponent, privateExponent, primeP, primeQ, exponent1, exponent2, coefficientCrt);
            KeyFactory factory = KeyFactory.getInstance("RSA");
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
            keyBytesString = keyBytesString.replace("-----BEGIN RSA PRIVATE KEY-----", "");
            keyBytesString = keyBytesString.replace("-----END RSA PRIVATE KEY-----", "");
            keyBytesString = keyBytesString.replace("\n", "");
            byte[] decodedKeyBytes = Base64.getDecoder().decode(keyBytesString.trim().getBytes());
            return this.parseDerKey(decodedKeyBytes);
        } catch (UnsupportedEncodingException e) {
            throw new KeyParserException(e);
        }
    }
}
