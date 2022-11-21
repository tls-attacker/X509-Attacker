/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.signatureengine;

import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import de.rub.nds.x509attacker.signatureengine.keyparsers.SignatureKeyType;

public class EcdsaWithSha256SignatureEngine extends JavaSignatureEngine {

    public EcdsaWithSha256SignatureEngine() {
        super(X509SignatureAlgorithm.ECDSA_WITH_SHA256, "ECDSAwithSHA256");
    }
}
