/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator.publickey;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.publickey.X509X448PublicKey;
import de.rub.nds.x509attacker.x509.preparator.X509Asn1FieldPreparator;

public class X448PublicKeyPreparator extends X509Asn1FieldPreparator<X509X448PublicKey> {

    public X448PublicKeyPreparator(X509Chooser chooser, X509X448PublicKey instance) {
        super(chooser, instance);
    }

    @Override
    protected byte[] encodeContent() {
        // X448 public keys are 56 bytes
        byte[] publicKey = chooser.getSubjectX448PublicKey();
        if (publicKey == null) {
            publicKey = chooser.getConfig().getDefaultSubjectX448PublicKey();
        }
        field.setContent(publicKey);
        return publicKey;
    }
}
