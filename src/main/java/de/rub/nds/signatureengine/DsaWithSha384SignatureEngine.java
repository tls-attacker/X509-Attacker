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

public class DsaWithSha384SignatureEngine extends JavaSignatureEngine {

    public static final String objectIdentifierString = "2.16.840.1.101.3.4.3.3";

    private static final String signatureAlgorithm = "SHA384withDSA";

    public static final String name = "DSAwithSHA384";

    public static final KeyType keyType = KeyType.DSA;

    public DsaWithSha384SignatureEngine() throws SignatureEngineException {
        super(signatureAlgorithm, new DefaultKeyParser());
    }
}
