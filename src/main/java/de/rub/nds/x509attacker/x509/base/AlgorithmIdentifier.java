/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.asn1.model.Asn1Any;
import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1Field;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AlgorithmIdentifier extends Asn1Sequence {

    private static final Logger LOGGER = LogManager.getLogger();

    @HoldsModifiableVariable
    private Asn1ObjectIdentifier algorithm;

    @HoldsModifiableVariable
    private final Asn1Any parameters;

    public AlgorithmIdentifier(String identifier) {
        super(identifier);
        algorithm = new Asn1ObjectIdentifier("algorithm");
        parameters = new Asn1Any("parameters");
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

    public void instantiateParameters(Asn1Field encodable) {
        parameters.setInstantiation(encodable);
    }
}
