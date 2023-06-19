/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model;

import de.rub.nds.asn1.model.Asn1Field;
import de.rub.nds.asn1.model.Asn1Null;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.parser.AlgorithmIdentifierParser;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.serializer.AlgorithmIdentifierSerializer;
import de.rub.nds.x509attacker.x509.serializer.X509Serializer;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public abstract class AlgorithmIdentifier extends Asn1Sequence implements X509Component {

    @HoldsModifiableVariable
    private Asn1ObjectIdentifier algorithm;

    @HoldsModifiableVariable
    private Asn1Field parameters;

    private AlgorithmIdentifier() {
        super(null);
        parameters = null;
    }

    public AlgorithmIdentifier(String identifier) {
        super(identifier);
        algorithm = new Asn1ObjectIdentifier("algorithm");
        parameters = new Asn1Null("parameters");
        parameters.setOptional(true);
        addChild(algorithm);
        addChild(parameters);
    }

    public Asn1ObjectIdentifier getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(Asn1ObjectIdentifier algorithm) {
        this.algorithm = algorithm;
    }

    public Asn1Field getParameters() {
        return parameters;
    }

    public void setParameters(Asn1Field parameters) {
        this.parameters = parameters;
    }

    @Override
    public final X509Parser getParser(X509Chooser chooser) {
        return new AlgorithmIdentifierParser(chooser, this);
    }

    @Override
    public final X509Serializer getSerializer(X509Chooser chooser) {
        return new AlgorithmIdentifierSerializer(chooser, this);
    }
}
