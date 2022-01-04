/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
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
