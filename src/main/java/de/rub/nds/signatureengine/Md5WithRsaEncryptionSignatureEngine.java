/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.signatureengine;

import de.rub.nds.signatureengine.keyparsers.DefaultKeyParser;
import de.rub.nds.signatureengine.keyparsers.KeyType;

public class Md5WithRsaEncryptionSignatureEngine extends JavaSignatureEngine {

    public static final String objectIdentifierString = "1.2.840.113549.1.1.1.4";

    private static final String signatureAlgorithm = "MD5withRSA";

    public static final String name = "MD5withRSA";

    public static final KeyType keyType = KeyType.RSA;

    public Md5WithRsaEncryptionSignatureEngine() {
        super(signatureAlgorithm, new DefaultKeyParser());
    }
}
