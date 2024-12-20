/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model.extensions;

import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.model.X509Component;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.serializer.X509Serializer;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAnyElement;
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * DistributionPoint ::= SEQUENCE { distributionPoint [0] DistributionPointName OPTIONAL, reasons
 * [1] ReasonFlags OPTIONAL, crlIssuer [2] GeneralNames OPTIONAL }
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class DistributionPoint extends Asn1Sequence implements X509Component {

    @HoldsModifiableVariable private DistributionPointName distributionPointName;

    @HoldsModifiableVariable private ReasonFlags reasons;

    @HoldsModifiableVariable
    @XmlAnyElement(lax = true)
    private GeneralNames crlIssuer;

    private DistributionPoint() {
        super(null);
    }

    private DistributionPoint(String identifier) {
        super(identifier);
        distributionPointName = new DistributionPointName(identifier);
        reasons = new ReasonFlags(identifier);
        crlIssuer = new GeneralNames("crlIssuer");
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

    public GeneralNames getCrlIssuer() {
        return crlIssuer;
    }

    public void setCrlIssuer(GeneralNames crlIssuer) {
        this.crlIssuer = crlIssuer;
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        throw new UnsupportedOperationException("not implemented yet");
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        throw new UnsupportedOperationException("not implemented yet");
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        throw new UnsupportedOperationException("not implemented yet");
    }

    @Override
    public X509Serializer getSerializer(X509Chooser chooser) {
        throw new UnsupportedOperationException("not implemented yet");
    }
}
