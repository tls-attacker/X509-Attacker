/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator;

import de.rub.nds.asn1.model.Asn1Field;
import de.rub.nds.asn1.preparator.Asn1FieldPreparator;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.X509Component;

public abstract class X509ComponentPreparator<Component extends Asn1Field>
        extends Asn1FieldPreparator<Component> {

    protected final X509Chooser chooser;

    protected X509Component component;

    /**
     * TODO not so nice.
     *
     * @param chooser
     * @param field
     */
    public X509ComponentPreparator(X509Chooser chooser, X509Component field) {
        super((Component) field);
        this.component = field;
        this.chooser = chooser;
    }

    @Override
    protected final byte[] encodeContent() {
        prepareSubComponents();
        return component.getSerializer(chooser).serialize();
    }

    public abstract void prepareSubComponents();
}
