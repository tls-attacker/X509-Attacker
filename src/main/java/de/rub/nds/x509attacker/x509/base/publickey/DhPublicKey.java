/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base.publickey;

import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.preparator.Preparator;
import de.rub.nds.asn1.serializer.Asn1FieldSerializer;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.X509Component;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.preparator.X509ComponentPreparator;
import de.rub.nds.x509attacker.x509.preparator.publickey.DhPublicKeyPreparator;

public class DhPublicKey extends Asn1Integer implements X509Component {

    public DhPublicKey() {
        super("dhPublicKey");
    }

    @Override
    public Preparator getGenericPreparator() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public X509ComponentPreparator getPreparator(X509Chooser chooser) {
        return new DhPublicKeyPreparator(this, chooser);
    }

    @Override
    public Asn1FieldSerializer getSerializer() {
        return super.getGenericSerializer();
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from
        // nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }
}
