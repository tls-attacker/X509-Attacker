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

import java.security.PrivateKey;

public interface KeyParser {
    PrivateKey parse(final byte[] keyBytes, final SignatureEngine.KeyType keyType) throws KeyParserException;
}
