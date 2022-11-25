/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator.publickey;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.publickey.RsaPublicKey;
import de.rub.nds.x509attacker.x509.preparator.X509ComponentPreparator;

public class RsaPublicKeyPreparator extends X509ComponentPreparator<RsaPublicKey> {

    public RsaPublicKeyPreparator(RsaPublicKey instance, X509Chooser chooser) {
        super(instance, chooser);
    }

    @Override
    protected byte[] encodeContent() {
        instance.getModulus().setValue(chooser.getConfig().getRsaModulus());
        prepareSubcomponent(instance.getModulus());
        instance.getPublicExponent().setValue(chooser.getConfig().getRsaPublicKey());
        prepareSubcomponent(instance.getPublicExponent());
        instance.setEncodedChildren(encodedChildren(instance.getChildren()));
        return instance.getEncodedChildren().getValue();
    }
}
