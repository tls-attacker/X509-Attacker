/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.signatureengine;

import de.rub.nds.x509attacker.signatureengine.keyparsers.KeyType;

public class DsaWithSha256SignatureEngine extends JavaSignatureEngine {

    public DsaWithSha256SignatureEngine() {
        super(KeyType.DSA, "2.16.840.1.101.3.4.3.2", "DSAwithSHA256", "SHA256withDSA");
    }
}
