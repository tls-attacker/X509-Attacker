/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.signatureengine;

import de.rub.nds.signatureengine.keyparsers.KeyType;

public class EcdsaWithSha512SignatureEngine extends JavaSignatureEngine {

    public EcdsaWithSha512SignatureEngine() {
        super(KeyType.ECDSA, "1.2.840.10045.4.3.4", "ECDSAwithSHA512", "ECDSAwithSHA512");
    }
}
