/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.constants;

import de.rub.nds.asn1.model.*;
import java.security.InvalidParameterException;

public enum DirectoryStringChoiceType {
    TELETEX_STRING,
    PRINTABLE_STRING,
    UNIVERSAL_STRING,
    UTF8_STRING,
    BMP_STRING;

    public static DirectoryStringChoiceType fromChoice(Asn1Encodable asn1Encodable) {
        if (asn1Encodable instanceof Asn1T61String) {
            return TELETEX_STRING;
        } else if (asn1Encodable instanceof Asn1PrintableString) {
            return PRINTABLE_STRING;
        } else if (asn1Encodable instanceof Asn1UniversalString) {
            return UNIVERSAL_STRING;
        } else if (asn1Encodable instanceof Asn1Utf8String) {
            return UTF8_STRING;
        } else if (asn1Encodable instanceof Asn1BmpString) {
            return BMP_STRING;
        } else {
            throw new InvalidParameterException(
                    asn1Encodable + "is not a valid choice for directory String.");
        }
    }
}
