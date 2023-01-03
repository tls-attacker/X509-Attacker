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
import de.rub.nds.x509attacker.x509.base.publickey.DsaPublicKey;
import de.rub.nds.x509attacker.x509.preparator.X509ComponentPreparator;

public class DsaPublicKeyPreparator extends X509ComponentPreparator<DsaPublicKey> {

    public DsaPublicKeyPreparator(DsaPublicKey instance, X509Chooser chooser) {
        super(instance, chooser);
    }

    @Override
    protected byte[] encodeContent() {
        instance.setY(chooser.getConfig().getDefaultIssuerDsaPublicKeyY());
        instance.getGenericPreparator().prepare();
        return instance.getGenericSerializer().serialize(); //TODO not sure this is correct
    }
}
