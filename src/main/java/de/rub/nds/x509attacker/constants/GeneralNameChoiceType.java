/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.constants;

/** This is the choice we will make when we create certificates */
public enum GeneralNameChoiceType {
    OTHER_NAME,
    RFC822_NAME,
    DNS_NAME,
    X400_ADDRESS,
    DIRECTORY_NAME,
    EDI_PARTY_NAME,
    UNIFORM_RESOURCE_IDENTIFIER,
    IP_ADDRESS,
    REGISTERED_ID;
}
