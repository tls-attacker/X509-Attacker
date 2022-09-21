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
 * Exception thrown the repair of a X509CertificateChain failed.
 *
 */
public class RepairChainException extends Exception {

    public RepairChainException() {
    }

    public RepairChainException(String message) {
        super(message);
    }

    public RepairChainException(String message, Throwable cause) {
        super(message, cause);
    }

    public RepairChainException(Throwable cause) {
        super(cause);
    }

    public RepairChainException(String message, Throwable cause, boolean enableSuppression,
        boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
