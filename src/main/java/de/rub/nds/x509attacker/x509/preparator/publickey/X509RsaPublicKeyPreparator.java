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
import de.rub.nds.x509attacker.x509.model.publickey.X509RsaPublicKey;
import de.rub.nds.x509attacker.x509.preparator.X509Asn1FieldPreparator;

public class X509RsaPublicKeyPreparator extends X509Asn1FieldPreparator<X509RsaPublicKey> {

    public X509RsaPublicKeyPreparator(X509Chooser chooser, X509RsaPublicKey instance) {
        super(chooser, instance);
    }

    @Override
    protected byte[] encodeContent() {
        field.getModulus().setValue(chooser.getConfig().getRsaModulus());
        field.getPublicExponent().setValue(chooser.getConfig().getRsaPublicExponent());
        field.getPreparator(chooser).prepare();
        field.setEncodedChildren(field.getSerializer(chooser).serialize());
        return field.getEncodedChildren().getValue();
    }
}
