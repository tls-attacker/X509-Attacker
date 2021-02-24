/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.signatureengine;

public class SignatureEngineException extends Exception {

    public SignatureEngineException(String message) {
        super(message);
    }

    public SignatureEngineException(Throwable cause) {
        super(cause);
    }
}
