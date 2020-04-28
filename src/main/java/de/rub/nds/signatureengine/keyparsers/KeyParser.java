package de.rub.nds.signatureengine.keyparsers;

import de.rub.nds.signatureengine.SignatureEngine;

import java.security.PrivateKey;

public interface KeyParser {
    PrivateKey parse(final byte[] keyBytes, final SignatureEngine.KeyFormat keyFormat) throws KeyParserException;
}
