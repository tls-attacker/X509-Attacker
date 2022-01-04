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

public class EngineTuple {

    private final String objectIdentifierString;

    private final Class<? extends SignatureEngine> signatureEngine;

    private final String name;

    private final KeyType keyType;

    public EngineTuple(final String objectIdentifierString, final Class<? extends SignatureEngine> signatureEngine,
        final String name, final KeyType keyType) {
        this.objectIdentifierString = objectIdentifierString;
        this.signatureEngine = signatureEngine;
        this.name = name;
        this.keyType = keyType;
    }

    public String getObjectIdentifierString() {
        return objectIdentifierString;
    }

    public Class<? extends SignatureEngine> getSignatureEngine() {
        return signatureEngine;
    }

    public String getName() {
        return name;
    }

    public KeyType getKeyType() {
        return keyType;
    }
}
