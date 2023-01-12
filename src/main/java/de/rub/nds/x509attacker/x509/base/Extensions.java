/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.asn1.handler.Handler;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.parser.Asn1SequenceParser;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.parser.ExtensionsParser;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

/** Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Extensions extends Asn1Sequence<X509Chooser> {

    private Extensions() {
        super(null);
    }

    public Extensions(String identifier) {
        super(identifier);
    }

    @Override
    public Asn1SequenceParser getParser(X509Chooser chooser) {
        return new ExtensionsParser(chooser, this);
    }

    @Override
    public Handler getHandler(X509Chooser chooser) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
