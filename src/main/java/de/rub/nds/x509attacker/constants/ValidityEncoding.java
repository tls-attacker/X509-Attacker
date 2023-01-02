/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.constants;

public enum ValidityEncoding {
    UTC,
    UTC_DIFFERENTIAL,
    GENERALIZED_TIME_LOCAL,
    GENERALIZED_TIME_UTC,
    GENERALIZED_TIME_DIFFERENTIAL
}
