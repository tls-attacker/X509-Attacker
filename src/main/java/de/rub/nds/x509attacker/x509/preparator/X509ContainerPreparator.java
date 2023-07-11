/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator;

import de.rub.nds.asn1.model.Asn1Container;
import de.rub.nds.asn1.preparator.Asn1FieldPreparator;
import de.rub.nds.x509attacker.chooser.X509Chooser;

public abstract class X509ContainerPreparator<Container extends Asn1Container>
        extends Asn1FieldPreparator<Container> implements X509Preparator {

    protected final X509Chooser chooser;

    /**
     * @param chooser
     * @param container
     */
    public X509ContainerPreparator(X509Chooser chooser, Container container) {
        super(container);
        this.chooser = chooser;
    }

    @Override
    protected final byte[] encodeContent() {
        prepareSubComponents();
        return encodeChildrenContent();
    }

    public abstract void prepareSubComponents();

    public abstract byte[] encodeChildrenContent();
}
