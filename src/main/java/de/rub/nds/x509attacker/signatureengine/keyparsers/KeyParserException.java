/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.signatureengine.keyparsers;

public class KeyParserException extends RuntimeException {

    public KeyParserException(String message) {
        super(message);
    }

    public KeyParserException(Throwable cause) {
        super(cause);
    }
}
