/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator.publickey;

import de.rub.nds.asn1.preparator.Asn1PreparatorHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.publickey.X509RsaPublicKey;
import de.rub.nds.x509attacker.x509.preparator.X509Asn1FieldPreparator;

public class X509RsaPublicKeyPreparator extends X509Asn1FieldPreparator<X509RsaPublicKey> {

    public X509RsaPublicKeyPreparator(X509Chooser chooser, X509RsaPublicKey instance) {
        super(chooser, instance);
    }

    @Override
    protected byte[] encodeContent() {
        Asn1PreparatorHelper.prepareField(field.getModulus(), chooser.getConfig().getRsaModulus());
        Asn1PreparatorHelper.prepareField(
                field.getPublicExponent(),
                chooser.getConfig().getDefaultSubjectRsaPublicExponent());
        field.setEncodedChildren(encodeChildren(field.getModulus(), field.getPublicExponent()));
        return field.getEncodedChildren().getValue();
    }
}
