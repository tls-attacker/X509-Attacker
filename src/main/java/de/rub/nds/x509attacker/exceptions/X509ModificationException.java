/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.exceptions;

/**
 * Exception thrown if a modification of a X509Certificate failed.
 *
 */
public class X509ModificationException extends Exception {

    public X509ModificationException() {
    }

    public X509ModificationException(String message) {
        super(message);
    }

    public X509ModificationException(String message, Throwable cause) {
        super(message, cause);
    }

    public X509ModificationException(Throwable cause) {
        super(cause);
    }

    public X509ModificationException(String message, Throwable cause, boolean enableSuppression,
        boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
