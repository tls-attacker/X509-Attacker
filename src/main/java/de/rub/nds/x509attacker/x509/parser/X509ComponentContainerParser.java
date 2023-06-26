/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser;

import de.rub.nds.asn1.model.Asn1Container;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.X509Component;
import java.io.BufferedInputStream;

/**
 * A parser for the X509 module that always parses the the structure of the asn1 field and then
 * passes the content of the field to the implementation
 */
public abstract class X509ComponentContainerParser<Encodable extends X509Component>
        extends X509ComponentFieldParser<Encodable> {

    protected final Asn1Container container;

    public X509ComponentContainerParser(X509Chooser chooser, Encodable encodable) {
        super(chooser, encodable);
        if (!(encodable instanceof Asn1Container)) {
            throw new IllegalArgumentException("Encodable must be an Asn1Container.");
        }
        this.container = (Asn1Container) encodable;
    }

    protected final void parseContent(BufferedInputStream inputStream) {
        container.setEncodedChildren(container.getContent().getValue());
        parseSubcomponents(inputStream);
    }

    protected abstract void parseSubcomponents(BufferedInputStream inputStream);
}
