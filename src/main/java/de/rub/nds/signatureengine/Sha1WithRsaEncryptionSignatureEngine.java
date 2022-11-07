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

public class Sha1WithRsaEncryptionSignatureEngine extends JavaSignatureEngine {

    public Sha1WithRsaEncryptionSignatureEngine() {
            super(KeyType.RSA, "1.2.840.113549.1.1.5", "RSAwithSHA1", "SHA1withRSA");
    }
}
