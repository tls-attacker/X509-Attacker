/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.extensions;

import de.rub.nds.asn1.model.Asn1Choice;
import de.rub.nds.asn1.preparator.Preparator;
import de.rub.nds.x509attacker.x509.base.RelativeDistinguishedName;

/**
 * DistributionPointName ::= CHOICE { fullName [0] GeneralNames, nameRelativeToCRLIssuer [1]
 * RelativeDistinguishedName }
 */
public class DistributionPointName extends Asn1Choice {

    public DistributionPointName(String identifier) {
        super(identifier, new GeneralNames(identifier), new RelativeDistinguishedName(identifier));
    }

    @Override
    public Preparator getGenericPreparator() {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from
        // nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }
}
