/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model.publickey.parameters;

import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.handler.publickey.parameters.X509EcNamedCurveParametersHandler;
import de.rub.nds.x509attacker.x509.parser.X509Asn1ObjectIdentifierParser;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.preparator.publickey.parameters.X509EcNamedCurveParametersPreparator;
import de.rub.nds.x509attacker.x509.serializer.X509Asn1FieldSerializer;
import de.rub.nds.x509attacker.x509.serializer.X509Serializer;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509EcNamedCurveParameters extends Asn1ObjectIdentifier implements PublicParameters {

    private X509EcNamedCurveParameters() {
        super(null);
    }

    public X509EcNamedCurveParameters(String identifier) {
        super("namedCurve");
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        return new X509EcNamedCurveParametersHandler(chooser, this);
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        return new X509Asn1ObjectIdentifierParser(chooser, this);
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        return new X509EcNamedCurveParametersPreparator(chooser, this);
    }

    @Override
    public X509Serializer getSerializer(X509Chooser chooser) {
        return new X509Asn1FieldSerializer(this);
    }
}
