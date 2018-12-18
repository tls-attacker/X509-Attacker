package de.rub.nds.x509attacker.x509.model.extensions.freshestcrl;

import de.rub.nds.x509attacker.x509.model.extensions.crldistributionpoints.CRLDistributionPoints;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class FreshestCRL extends CRLDistributionPoints {

    public FreshestCRL() {
        super();
    }
}
