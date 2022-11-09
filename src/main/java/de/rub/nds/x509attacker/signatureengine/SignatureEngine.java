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
import java.security.PrivateKey;

public abstract class SignatureEngine {

    private final KeyType keyType;

    final String oid;

    private final String name;

    public SignatureEngine(KeyType keyType, String oid, String name) {
        this.keyType = keyType;
        this.oid = oid;
        this.name = name;
    }

    public String getOid() {
        return oid;
    }

    public String getName() {
        return name;
    }

    public KeyType getKeyType() {
        return keyType;
    }

    /**
     * Signs the given data and returns the signature value.Cannot be called before the signature engine is initialized.
     *
     * @param  privateKey
     * @param  toBeSigned
     *                                                             The data to be signed.
     * @return                                                     The signature value.
     * @throws de.rub.nds.x509attacker.signatureengine.SignatureEngineException
     *                                                             when the signing fails
     */
    public abstract byte[] sign(PrivateKey privateKey, final byte[] toBeSigned) throws SignatureEngineException;

}
