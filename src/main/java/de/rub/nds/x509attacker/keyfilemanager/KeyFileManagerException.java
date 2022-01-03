/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.keyfilemanager;

public class KeyFileManagerException extends Exception {

    public KeyFileManagerException(String message) {
        super(message);
    }

    public KeyFileManagerException(Throwable cause) {
        super(cause);
    }
}
