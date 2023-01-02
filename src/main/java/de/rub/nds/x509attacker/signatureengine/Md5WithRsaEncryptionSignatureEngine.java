/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.signatureengine;

import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;

public class Md5WithRsaEncryptionSignatureEngine extends JavaSignatureEngine {

    public Md5WithRsaEncryptionSignatureEngine() {
        super(X509SignatureAlgorithm.MD5_WITH_RSA_ENCRYPTION, "MD5withRSA");
    }
}
