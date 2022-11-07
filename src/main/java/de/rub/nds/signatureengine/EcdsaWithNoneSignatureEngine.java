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

public class EcdsaWithNoneSignatureEngine extends JavaSignatureEngine {

    public EcdsaWithNoneSignatureEngine() {
        super(KeyType.ECDSA, null, "NONEWithECDSA", "NONEWithECDSA");
        //OID is null because this is not officially defined
    }
}
