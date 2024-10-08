/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.signatureengine.keyparsers;

import de.rub.nds.x509attacker.constants.KeyFormat;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;

public class DefaultKeyParser implements KeyParser {

    public DefaultKeyParser() {}

    @Override
    public final PrivateKey parsePrivateKey(final byte[] keyBytes, final KeyFormat keyFormat) {
        switch (keyFormat) {
            case PEM_ENCODED:
                return this.parsePemPrivateKey(keyBytes);
            default:
                throw new KeyParserException(
                        "Key format " + keyFormat + " not supported by key parser!");
        }
    }

    @Override
    public final PublicKey parsePublicKey(final byte[] keyBytes, final KeyFormat keyFormat) {
        switch (keyFormat) {
            case PEM_ENCODED:
                return this.parsePemPublicKey(keyBytes);
            default:
                throw new KeyParserException(
                        "Key format " + keyFormat + " not supported by key parser!");
        }
    }

    protected PrivateKey parsePemPrivateKey(final byte[] keyBytes) {
        InputStream keyBytesInputSteam = new ByteArrayInputStream(keyBytes);
        return PemUtil.readPrivateKey(keyBytesInputSteam);
    }

    protected PublicKey parsePemPublicKey(final byte[] keyBytes) {
        InputStream keyBytesInputSteam = new ByteArrayInputStream(keyBytes);
        return PemUtil.readPublicKey(keyBytesInputSteam);
    }
}
