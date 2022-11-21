/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.asn1.model.Asn1Choice;
import de.rub.nds.asn1.model.Asn1PrimitiveGeneralizedTime;
import de.rub.nds.asn1.model.Asn1PrimitiveUtcTime;
import de.rub.nds.asn1.preparator.Preparator;
import de.rub.nds.asn1.serializer.Asn1FieldSerializer;

/**
 *
 * Time ::= CHOICE { utcTime UTCTime, generalTime GeneralizedTime }
 *
 */
public class Time extends Asn1Choice {

    public Time(String identifier) {
        super(identifier, new Asn1PrimitiveUtcTime("utcTime"), new Asn1PrimitiveGeneralizedTime(identifier));
    }

    @Override
    public Asn1FieldSerializer getSerializer() {
        return super.getSerializer(); // Generated from
                                      // nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/OverriddenMethodBody
    }

    @Override
    public Preparator getPreparator() {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from
                                                                       // nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

}
