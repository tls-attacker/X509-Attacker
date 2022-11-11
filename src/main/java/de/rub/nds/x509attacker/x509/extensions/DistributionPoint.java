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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * DistributionPoint ::= SEQUENCE { distributionPoint [0] DistributionPointName OPTIONAL, reasons [1] ReasonFlags
 * OPTIONAL, cRLIssuer [2] GeneralNames OPTIONAL }
 *
 */
public class DistributionPoint extends Asn1Sequence {

    private static final Logger LOGGER = LogManager.getLogger();

    private DistributionPointName distributionPointName;
    private ReasonFlags reasons;
    private GeneralNames cRLIssuer;

    private DistributionPoint(String identifier) {
        super(identifier);
    }

    public DistributionPointName getDistributionPointName() {
        return distributionPointName;
    }

    public void setDistributionPointName(DistributionPointName distributionPointName) {
        this.distributionPointName = distributionPointName;
    }

    public ReasonFlags getReasons() {
        return reasons;
    }

    public void setReasons(ReasonFlags reasons) {
        this.reasons = reasons;
    }

    public GeneralNames getcRLIssuer() {
        return cRLIssuer;
    }

    public void setcRLIssuer(GeneralNames cRLIssuer) {
        this.cRLIssuer = cRLIssuer;
    }

}
