/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

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
    public final PrivateKey parse(final byte[] keyBytes, final SignatureEngine.KeyType keyType)
        throws KeyParserException {
        PrivateKey privateKey = null;
        switch (keyType) {
            case PEM_ENCODED:
                privateKey = this.parsePemKey(keyBytes);
                break;

            default:
                throw new KeyParserException("Key type " + keyType + " not supported by key parser!");
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
