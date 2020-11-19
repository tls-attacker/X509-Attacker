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

public class KeyParserException extends Exception {

    public KeyParserException(String message) {
        super(message);
    }

    public KeyParserException(Throwable cause) {
        super(cause);
    }
}
