/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator.publickey.parameters;

import de.rub.nds.asn1.preparator.Asn1FieldPreparator;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.publickey.parameters.X509DssParameters;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;

public class DssParameterPreparator extends Asn1FieldPreparator<X509DssParameters>
        implements X509Preparator {

    private X509DssParameters parameters;
    private X509Chooser chooser;

    public DssParameterPreparator(X509Chooser chooser, X509DssParameters parameters) {
        super(parameters);
        this.chooser = chooser;
        this.parameters = parameters;
    }

    @Override
    protected byte[] encodeContent() {
        prepareField(parameters.getQ(), chooser.getConfig().getDsaPrimeQ());
        prepareField(parameters.getG(), chooser.getConfig().getDsaGenerator());
        prepareField(parameters.getP(), chooser.getConfig().getDsaPrimeP());
        parameters.setEncodedChildren(encodedChildren(parameters.getChildren()));
        return parameters.getEncodedChildren().getValue();
    }
}
