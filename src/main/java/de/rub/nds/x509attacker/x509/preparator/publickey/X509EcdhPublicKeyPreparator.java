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
import de.rub.nds.protocol.crypto.ec.Point;
import de.rub.nds.protocol.crypto.ec.PointFormatter;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.publickey.X509EcdhPublicKey;
import de.rub.nds.x509attacker.x509.preparator.X509Asn1FieldPreparator;

public class X509EcdhPublicKeyPreparator extends X509Asn1FieldPreparator<X509EcdhPublicKey> {

    public X509EcdhPublicKeyPreparator(X509Chooser chooser, X509EcdhPublicKey instance) {
        super(chooser, instance);
    }

    @Override
    protected byte[] encodeContent() {
        Point publicKey = chooser.getConfig().getDefaultSubjectEcPublicKey();
        Asn1PreparatorHelper.prepareField(
                field,
                PointFormatter.formatToByteArray(
                        chooser.getConfig().getDefaultSubjectNamedCurve().getParameters(),
                        publicKey,
                        chooser.getConfig().getDefaultEcPointFormat()));
        field.setxCoordinate(publicKey.getFieldX().getData());
        field.setyCoordinate(publicKey.getFieldY().getData());
        return field.getContent()
                .getOriginalValue(); // We return the original value here, otherwise we will modify
    }
}
