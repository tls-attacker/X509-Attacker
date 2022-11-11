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

/**
 *
 * Validity ::= SEQUENCE { notBefore Time, notAfter Time }
 *
 */
public class Validity extends Asn1Sequence {

    private Time notBefore;
    private Time notAfter;

    public Validity(String identifier) {
        super(identifier);
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
