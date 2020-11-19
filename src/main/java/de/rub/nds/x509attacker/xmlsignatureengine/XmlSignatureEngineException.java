/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.x509attacker.xmlsignatureengine;

public class XmlSignatureEngineException extends RuntimeException {

    public XmlSignatureEngineException(String message) {
        super(message);
    }

    public XmlSignatureEngineException(String message, Throwable cause) {
        super(message, cause);
    }

    public XmlSignatureEngineException(Throwable cause) {
        super(cause);
    }
}
