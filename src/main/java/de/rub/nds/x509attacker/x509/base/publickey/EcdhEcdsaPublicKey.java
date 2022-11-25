/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base.publickey;

import de.rub.nds.asn1.model.Asn1PrimitiveBitString;
import de.rub.nds.asn1.serializer.Asn1FieldSerializer;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.X509Component;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.preparator.X509ComponentPreparator;

public class EcdhEcdsaPublicKey extends Asn1PrimitiveBitString implements X509Component {

    public EcdhEcdsaPublicKey() {
        super("ecPublicKey");
    }

    @Override
    public X509ComponentPreparator getPreparator(X509Chooser chooser) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Asn1FieldSerializer getSerializer() {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
