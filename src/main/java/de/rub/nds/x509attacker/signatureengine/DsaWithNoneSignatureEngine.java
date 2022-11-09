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

public class DsaWithNoneSignatureEngine extends JavaSignatureEngine {

    public DsaWithNoneSignatureEngine() {
        super(KeyType.DSA, null, "NONEwithDSA", "NONEwithDSA");
        // oid is null because NONEwithDSA is not officially defined
    }
}
