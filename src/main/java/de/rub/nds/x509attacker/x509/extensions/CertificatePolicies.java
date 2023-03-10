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
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElementRef;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.LinkedList;
import java.util.List;

/** certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class CertificatePolicies extends Asn1Sequence<X509Chooser> {

    @XmlElementWrapper @XmlElementRef @HoldsModifiableVariable
    private List<PolicyInformation> policyInformation;

    private CertificatePolicies() {
        super(null);
    }

    public CertificatePolicies(String identifier) {
        super(identifier);
        policyInformation = new LinkedList<>();
    }

    public List<PolicyInformation> getPolicyInformation() {
        return policyInformation;
    }

    public void setPolicyInformation(List<PolicyInformation> policyInformation) {
        this.policyInformation = policyInformation;
    }

    @Override
    public Handler<X509Chooser> getHandler(X509Chooser chooser) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
