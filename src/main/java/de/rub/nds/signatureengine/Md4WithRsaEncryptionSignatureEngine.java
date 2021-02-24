/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.signatureengine;

import de.rub.nds.signatureengine.keyparsers.DefaultKeyParser;

public class Md4WithRsaEncryptionSignatureEngine extends JavaSignatureEngine {

    public static final String objectIdentifierString = "1.2.840.113549.1.1.1.3";

    private static final String signatureAlgorithm = "MD4withRSA";

    public Md4WithRsaEncryptionSignatureEngine() throws SignatureEngineException {
        super(signatureAlgorithm, new DefaultKeyParser());
    }
}
