/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.signatureengine;

import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;

public class DsaWithSha512SignatureEngine extends JavaSignatureEngine {

    public DsaWithSha512SignatureEngine() {
        super(X509SignatureAlgorithm.DSA_WITH_SHA512, "SHA512withDSA");
    }
}
