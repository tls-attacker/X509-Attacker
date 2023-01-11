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
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import jakarta.xml.bind.annotation.XmlElementRef;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint */
public class CRLDistributionPoints extends Asn1Sequence<X509Chooser> {

    private static final Logger LOGGER = LogManager.getLogger();

    @XmlElementWrapper @XmlElementRef @HoldsModifiableVariable
    private List<DistributionPoint> distributionPoint;

    public CRLDistributionPoints(String identifier) {
        super(identifier);
        distributionPoint = new LinkedList<>();
    }

    public List<DistributionPoint> getDistributionPoint() {
        return distributionPoint;
    }

    public void setDistributionPoint(List<DistributionPoint> distributionPoint) {
        this.distributionPoint = distributionPoint;
    }
    
    @Override
    public Handler getHandler(X509Chooser chooser) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
