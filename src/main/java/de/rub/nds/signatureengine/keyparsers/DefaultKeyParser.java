package de.rub.nds.signatureengine.keyparsers;

import de.rub.nds.signatureengine.SignatureEngine;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;

public class DefaultKeyParser implements KeyParser {

    public DefaultKeyParser() {

    }

    @Override
    public final PrivateKey parse(final byte[] keyBytes, final SignatureEngine.KeyFormat keyFormat) throws KeyParserException {
        PrivateKey privateKey = null;
        switch (keyFormat) {
            case PEM_ENCODED:
                privateKey = this.parsePemKey(keyBytes);
                break;

            default:
                throw new KeyParserException("Key format " + keyFormat + " not supported by key parser!");
        }
        return privateKey;
    }

    protected PrivateKey parsePemKey(final byte[] keyBytes) throws KeyParserException {
        try {
            InputStream keyBytesInputSteam = new ByteArrayInputStream(keyBytes);
            return PemUtil.readPrivateKey(keyBytesInputSteam);
        } catch (IOException e) {
            throw new KeyParserException(e);
        }
    }
}
