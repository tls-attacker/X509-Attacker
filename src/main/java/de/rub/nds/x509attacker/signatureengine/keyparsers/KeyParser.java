package de.rub.nds.x509attacker.signatureengine.keyparsers;

import de.rub.nds.x509attacker.signatureengine.SignatureEngine;

import java.security.PrivateKey;

public interface KeyParser {
    PrivateKey parse(final byte[] keyBytes, final SignatureEngine.KeyType keyType) throws KeyParserException;
}
