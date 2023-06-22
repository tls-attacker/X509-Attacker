/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator.publickey;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.publickey.X509DsaPublicKey;
import de.rub.nds.x509attacker.x509.preparator.X509Asn1FieldPreparator;

public class X509DsaPublicKeyPreparator extends X509Asn1FieldPreparator<X509DsaPublicKey> {

    public X509DsaPublicKeyPreparator(X509DsaPublicKey instance, X509Chooser chooser) {
        super(chooser, instance);
    }

    @Override
    protected byte[] encodeContent() {
        prepareField(field, chooser.getConfig().getDsaPublicKeyY());
        return field.getContent()
                .getOriginalValue(); // We return the original value here, otherwise we will modify
        // it twice
    }
}
