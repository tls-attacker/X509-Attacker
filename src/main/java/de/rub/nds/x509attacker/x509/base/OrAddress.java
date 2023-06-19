/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.serializer.X509Serializer;

public class OrAddress extends Asn1Sequence implements X509Component {

    public OrAddress(String identifier) {
        super(identifier);
    }

    public OrAddress(String identifier, int implicitTagNumber) {
        super(identifier, implicitTagNumber);
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        throw new UnsupportedOperationException("Unimplemented method 'getHandler'");
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        throw new UnsupportedOperationException("Unimplemented method 'getParser'");
    }

    @Override
    public X509Serializer getSerializer(X509Chooser chooser) {
        throw new UnsupportedOperationException("Unimplemented method 'getSerializer'");
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        throw new UnsupportedOperationException("Unimplemented method 'getPreparator'");
    }
}
