/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.asn1.model.Asn1Any;
import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.model.PrimitiveAsn1Field;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public abstract class AlgorithmIdentifier extends Asn1Sequence implements X509Component{

    @HoldsModifiableVariable private Asn1ObjectIdentifier algorithm;

    @HoldsModifiableVariable private final Asn1Any parameters;

    private AlgorithmIdentifier() {
        super(null);
        parameters = null;
    }

    public AlgorithmIdentifier(String identifier) {
        super(identifier);
        algorithm = new Asn1ObjectIdentifier("algorithm");
        parameters = new Asn1Any("parameters");
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

    public Asn1Encodable getParameters() {
        return parameters;
    }

    public void instantiateParameters(PrimitiveAsn1Field encodable) {
        parameters.setInstantiation(encodable);
    }
}
