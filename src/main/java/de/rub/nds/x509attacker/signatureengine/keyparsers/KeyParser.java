/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.signatureengine.keyparsers;

import de.rub.nds.x509attacker.constants.KeyFormat;
import java.security.PrivateKey;
import java.security.PublicKey;

public interface KeyParser {

    public PrivateKey parsePrivateKey(final byte[] keyBytes, final KeyFormat keyFormat)
            throws KeyParserException;

    public PublicKey parsePublicKey(final byte[] keyBytes, final KeyFormat keyFormat)
            throws KeyParserException;
}
