/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.extensions;

import de.rub.nds.asn1.handler.Handler;
import de.rub.nds.asn1.model.Asn1Choice;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.RelativeDistinguishedName;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * DistributionPointName ::= CHOICE { fullName [0] GeneralNames, nameRelativeToCRLIssuer [1]
 * RelativeDistinguishedName }
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class DistributionPointName extends Asn1Choice<X509Chooser> {

    private DistributionPointName() {
        super(null);
    }

    public DistributionPointName(String identifier) {
        super(identifier, new GeneralNames(identifier), new RelativeDistinguishedName(identifier));
    }

    @Override
    public Handler getHandler(X509Chooser chooser) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
