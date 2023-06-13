/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator.publickey.parameters;

import de.rub.nds.asn1.preparator.Asn1SequencePreparator;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.publickey.parameters.X509DssParameters;

public class DssParameterPreparator extends Asn1SequencePreparator {

    private X509DssParameters parameters;

    public DssParameterPreparator(X509Chooser chooser, X509DssParameters parameters) {
        super(chooser, parameters);
        this.parameters = parameters;
    }

    @Override
    protected byte[] encodeContent() {
        parameters.getQ().setValue(chooser.getConfig().getDsaPrimeQ());
        parameters.getQ().getPreparator(chooser).prepare();
        parameters.getG().setValue(chooser.getConfig().getDsaGenerator());
        parameters.getG().getPreparator(chooser).prepare();
        parameters.getP().setValue(chooser.getConfig().getDsaPrimeP());
        parameters.getP().getPreparator(chooser).prepare();
        parameters.setEncodedChildren(encodedChildren(parameters.getChildren()));
        return parameters.getEncodedChildren().getValue();
    }
}
