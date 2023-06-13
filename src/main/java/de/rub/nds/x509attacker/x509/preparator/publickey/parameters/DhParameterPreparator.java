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
import de.rub.nds.x509attacker.x509.base.publickey.parameters.X509DhParameters;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;

public class DhParameterPreparator extends Asn1SequencePreparator implements X509Preparator {

    private X509DhParameters parameters;

    public DhParameterPreparator(X509Chooser chooser, X509DhParameters parameters) {
        super(chooser, parameters);
        this.parameters = parameters;
    }

    @Override
    protected byte[] encodeContent() {
        parameters.getG().setValue(chooser.getConfig().getDhGenerator());
        parameters.getP().setValue(chooser.getConfig().getDhModulus());
        parameters.setEncodedChildren(encodedChildren(parameters.getChildren()));
        return parameters.getEncodedChildren().getValue();
    }
}
