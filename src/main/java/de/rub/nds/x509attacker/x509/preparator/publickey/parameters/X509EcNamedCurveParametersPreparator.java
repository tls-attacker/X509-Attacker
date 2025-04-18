/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator.publickey.parameters;

import de.rub.nds.asn1.preparator.Asn1PreparatorHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.publickey.parameters.X509EcNamedCurveParameters;
import de.rub.nds.x509attacker.x509.preparator.X509Asn1FieldPreparator;

public class X509EcNamedCurveParametersPreparator
        extends X509Asn1FieldPreparator<X509EcNamedCurveParameters> {

    public X509EcNamedCurveParametersPreparator(
            X509Chooser chooser, X509EcNamedCurveParameters x509EcNamedCurveParameters) {
        super(chooser, x509EcNamedCurveParameters);
    }

    @Override
    protected byte[] encodeContent() {
        Asn1PreparatorHelper.prepareField(
                field, chooser.getConfig().getDefaultSubjectNamedCurve().getOid());
        return field.getContent().getValue();
    }
}
