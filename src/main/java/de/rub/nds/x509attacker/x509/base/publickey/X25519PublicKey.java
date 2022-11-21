/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509.base.publickey;

import de.rub.nds.asn1.model.Asn1PrimitiveBitString;

public class X25519PublicKey extends Asn1PrimitiveBitString implements SubjectPublicKey {

    public X25519PublicKey() {
        super("x25519PublicKey");
    }

}
