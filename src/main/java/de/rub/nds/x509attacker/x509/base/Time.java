/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.asn1.model.Asn1Choice;
import de.rub.nds.asn1.model.Asn1PrimitiveGeneralizedTime;
import de.rub.nds.asn1.model.Asn1PrimitiveUtcTime;
import de.rub.nds.x509attacker.chooser.X509Chooser;

/** Time ::= CHOICE { utcTime UTCTime, generalTime GeneralizedTime } */
public class Time extends Asn1Choice<X509Chooser> {

    public Time(String identifier) {
        super(
                identifier,
                new Asn1PrimitiveUtcTime<X509Chooser>("utcTime"),
                new Asn1PrimitiveGeneralizedTime<X509Chooser>("generalizedTime"));
    }
}
