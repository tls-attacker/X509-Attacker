/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509.extensions;

import de.rub.nds.asn1.model.Asn1Sequence;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
 *
 */
public class CRLDistributionPoints extends Asn1Sequence {

    private static final Logger LOGGER = LogManager.getLogger();

    private List<DistributionPoint> distributionPoint;

    public CRLDistributionPoints(String identifier) {
        super(identifier);
    }

    public List<DistributionPoint> getDistributionPoint() {
        return distributionPoint;
    }

    public void setDistributionPoint(List<DistributionPoint> distributionPoint) {
        this.distributionPoint = distributionPoint;
    }
}
