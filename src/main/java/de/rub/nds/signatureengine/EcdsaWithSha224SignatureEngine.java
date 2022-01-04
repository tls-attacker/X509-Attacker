/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.signatureengine;

import de.rub.nds.signatureengine.JavaSignatureEngine;
import de.rub.nds.signatureengine.SignatureEngineException;
import de.rub.nds.signatureengine.keyparsers.DefaultKeyParser;
import de.rub.nds.signatureengine.keyparsers.KeyType;

public class EcdsaWithSha224SignatureEngine extends JavaSignatureEngine {

    public static final String objectIdentifierString = "1.2.840.10045.4.3.1";

    private static final String signatureAlgorithm = "SHA224withECDSA";

    public static final String name = "ECDSAwithSHA224";

    public static final KeyType keyType = KeyType.ECDSA;

    public EcdsaWithSha224SignatureEngine() throws SignatureEngineException {
        super(signatureAlgorithm, new DefaultKeyParser());
    }
}
