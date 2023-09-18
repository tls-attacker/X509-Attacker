/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model;

import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.OrAddressHandler;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.parser.OrAddressParser;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.OrAddressPreparator;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;

public class OrAddress extends Asn1Sequence implements X509Component {

    public OrAddress(String identifier) {
        super(identifier);
    }

    public OrAddress(String identifier, int implicitTagNumber) {
        super(identifier, implicitTagNumber);
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        return new OrAddressHandler(chooser, this);
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        return new OrAddressParser(chooser, this);
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        return new OrAddressPreparator(chooser, this);
    }
}
