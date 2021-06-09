/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.constants;

public enum X509CertChainOutFormat {
    CHAIN_ALL_IND_ROOT_TO_LEAF,
    CHAIN_COMBINED,
    CHAIN_GROUPED3,
    CHAIN_GROUPED2,

    ROOT_CERT,
    LEAF_CERT,
    INTER_CERTS,
    INTER_CERTS_COMBINED,
    INTER_LEAF_CERTS_COMBINED,
    ROOT_INTER_LEAF_CERTS_COMBINED,
    LEAF_INTER_ROOT_CERTS_COMBINED

}