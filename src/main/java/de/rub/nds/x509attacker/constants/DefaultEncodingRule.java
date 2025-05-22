/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.constants;

/** Enumerator for encoding rules of optionals in extensions. */
public enum DefaultEncodingRule {
    // forces encoding
    ENCODE,
    // forces no encoding
    OMIT,
    // only encode field, if not default value as standardized
    FOLLOW_DEFAULT
}
