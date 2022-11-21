/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;

/**
 *
 * Validity ::= SEQUENCE { notBefore Time, notAfter Time }
 *
 */
public class Validity extends Asn1Sequence {

    @HoldsModifiableVariable
    private Time notBefore;

    @HoldsModifiableVariable
    private Time notAfter;

    public Validity(String identifier) {
        super(identifier);
        notBefore = new Time("notBefore");
        notAfter = new Time("notAfter");
        addChild(notBefore);
        addChild(notAfter);
    }

    public Time getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(Time notBefore) {
        this.notBefore = notBefore;
    }

    public Time getNotAfter() {
        return notAfter;
    }

    public void setNotAfter(Time notAfter) {
        this.notAfter = notAfter;
    }
}
