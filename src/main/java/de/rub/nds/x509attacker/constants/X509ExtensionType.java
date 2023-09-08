/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.constants;

public enum X509ExtensionType {
    KEY_USAGE,
    EXTENDED_KEY_USAGE,
    BASIC_CONSTRAINTS,
    SUBJECT_KEY_IDENTIFIER,
    AUTHORITY_KEY_IDENTIFIER,
    SUBJECT_ALTERNATIVE_NAME,
    ISSUER_ALTERNATIVE_NAME,
    CRL_DISTRIBUTION_POINTS,
    NETSCAPE_CERTIFICATE_TYPE,
    AUTHORITY_INFORMATION_ACCESS,
    CERTIFICATE_POLICIES,
    NAME_CONSTRAINTS,
    OCSP_NO_CHECK,
    POLICY_CONSTRAINTS,
    POLICY_MAPPINGS,
    PRIVATE_KEY_USAGE_PERIOD,
    SUBJECT_DIRECTORY_ATTRIBUTES,
}
