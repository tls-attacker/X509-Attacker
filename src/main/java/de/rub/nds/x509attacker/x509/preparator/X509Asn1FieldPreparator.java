/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator;

import de.rub.nds.asn1.model.Asn1Field;
import de.rub.nds.asn1.preparator.Asn1FieldPreparator;
import de.rub.nds.x509attacker.chooser.X509Chooser;

public abstract class X509Asn1FieldPreparator<Field extends Asn1Field>
        extends Asn1FieldPreparator<Field> implements X509Preparator {

    protected final X509Chooser chooser;

    public X509Asn1FieldPreparator(X509Chooser chooser, Field field) {
        super(field);
        this.chooser = chooser;
    }
}
