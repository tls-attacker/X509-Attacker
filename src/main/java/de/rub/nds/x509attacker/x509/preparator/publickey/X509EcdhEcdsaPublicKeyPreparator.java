/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator.publickey;

import de.rub.nds.asn1.preparator.Asn1PreparatorHelper;
import de.rub.nds.protocol.constants.PointFormat;
import de.rub.nds.protocol.crypto.ec.PointFormatter;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.publickey.X509EcdhEcdsaPublicKey;
import de.rub.nds.x509attacker.x509.preparator.X509Asn1FieldPreparator;

public class X509EcdhEcdsaPublicKeyPreparator
        extends X509Asn1FieldPreparator<X509EcdhEcdsaPublicKey> {

    public X509EcdhEcdsaPublicKeyPreparator(X509Chooser chooser, X509EcdhEcdsaPublicKey instance) {
        super(chooser, instance);
    }

    @Override
    protected byte[] encodeContent() {
        Asn1PreparatorHelper.prepareField(
                field,
                PointFormatter.formatToByteArray(
                        chooser.getConfig().getDefaultSubjectNamedCurve().getParameters(),
                        chooser.getConfig().getEcPublicKey(),
                        PointFormat.UNCOMPRESSED)); // TODO hardcoded uncompressed
        return field.getContent()
                .getOriginalValue(); // We return the original value here, otherwise we will modify
    }
}
