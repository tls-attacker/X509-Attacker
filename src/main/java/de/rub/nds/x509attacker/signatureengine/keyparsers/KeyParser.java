package de.rub.nds.x509attacker.signatureengine.keyparsers;

import de.rub.nds.x509attacker.signatureengine.SignatureEngine;

import java.security.PrivateKey;

public abstract class KeyParser {

    protected KeyParser() {

    }

    public final PrivateKey parse(final byte[] keyBytes, final SignatureEngine.KeyType keyType) throws KeyParserException {
        PrivateKey privateKey = null;
        switch (keyType) {
            case RAW_KEY:
                privateKey = this.parseRawKey(keyBytes);
                break;

            case DER_ENCODED:
                privateKey = this.parseDerKey(keyBytes);
                break;

            case PEM_ENCODED:
                privateKey = this.parsePemKey(keyBytes);
                break;

            default:
                throw new KeyParserException("Key type " + keyType + " not supported by key parser!");
        }
        return privateKey;
    }

    private void throwMissingImplementationKeyParseException() throws KeyParserException {
        throw new KeyParserException("Implementation is missing in this type of key parser for the given key type!");
    }

    protected PrivateKey parseRawKey(final byte[] keyBytes) throws KeyParserException {
        this.throwMissingImplementationKeyParseException();
        return null;
    }

    protected PrivateKey parseDerKey(final byte[] keyBytes) throws KeyParserException {
        this.throwMissingImplementationKeyParseException();
        return null;
    }

    protected PrivateKey parsePemKey(final byte[] keyBytes) throws KeyParserException {
        this.throwMissingImplementationKeyParseException();
        return null;
    }
}
