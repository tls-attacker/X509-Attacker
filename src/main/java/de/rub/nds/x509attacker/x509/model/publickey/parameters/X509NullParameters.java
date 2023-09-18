/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model.publickey.parameters;

import de.rub.nds.asn1.model.Asn1Null;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.handler.publickey.parameters.X509NullParametersHandler;
import de.rub.nds.x509attacker.x509.parser.X509Asn1NullParser;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.X509NullPreparator;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509NullParameters extends Asn1Null implements PublicParameters {

    private X509NullParameters() {
        super(null);
    }

    public X509NullParameters(String identifier) {
        super(identifier);
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        return new X509NullParametersHandler(chooser, this);
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        return new X509Asn1NullParser(chooser, this);
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        return new X509NullPreparator(chooser, this);
    }
}
