/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.asn1.model.Asn1PrimitiveGeneralizedTime;
import de.rub.nds.asn1.model.Asn1PrimitiveUtcTime;

/**
 *
 * Time ::= CHOICE { utcTime UTCTime, generalTime GeneralizedTime }
 *
 */
public class Time {

    private Asn1PrimitiveUtcTime utcTime;
    private Asn1PrimitiveGeneralizedTime generalizedTime;

    private final String identifier;

    public Time(String identifier) {
        this.identifier = identifier;
    }

    public Asn1PrimitiveUtcTime getUtcTime() {
        return utcTime;
    }

    public void setUtcTime(Asn1PrimitiveUtcTime utcTime) {
        this.utcTime = utcTime;
    }

    public Asn1PrimitiveGeneralizedTime getGeneralizedTime() {
        return generalizedTime;
    }

    public void setGeneralizedTime(Asn1PrimitiveGeneralizedTime generalizedTime) {
        this.generalizedTime = generalizedTime;
    }
}
