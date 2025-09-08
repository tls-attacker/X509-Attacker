/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model.extensions;

import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.model.GeneralName;
import de.rub.nds.x509attacker.x509.model.X509Component;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.preparator.extension.GeneralSubtreePreparator;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * GeneralSubtree ::= SEQUENCE { base GeneralName, minimum [0] BaseDistance DEFAULT 0, maximum [1]
 * BaseDistance OPTIONAL }
 *
 * <p>BaseDistance ::= INTEGER (0..MAX)
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class GeneralSubtree extends Asn1Sequence implements X509Component {

    @HoldsModifiableVariable private GeneralName base;
    @HoldsModifiableVariable private Asn1Integer minimum;
    @HoldsModifiableVariable private Asn1Integer maximum;

    // used values for preparation
    private long minimumValue;
    private long maximumValue;
    private boolean includeMinimum;
    private boolean includeMaximum;

    private GeneralSubtree() {
        super(null);
    }

    public GeneralSubtree(String identifier) {
        super(identifier);
        base = new GeneralName("base");
        minimum = new Asn1Integer("minimum");
        maximum = new Asn1Integer("maximum");

        includeMinimum = false;
        includeMaximum = false;
    }

    public GeneralSubtree(String identifier, long minimumValue, long maximumValue) {
        super(identifier);
        base = new GeneralName("base");
        minimum = new Asn1Integer("minimum");
        maximum = new Asn1Integer("maximum");

        this.minimumValue = minimumValue;
        this.maximumValue = maximumValue;
        includeMinimum = true;
        includeMaximum = true;
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
        return new GeneralSubtreePreparator(chooser, this);
    }

    public GeneralName getBase() {
        return base;
    }

    public void setBase(GeneralName base) {
        this.base = base;
    }

    public Asn1Integer getMinimum() {
        return minimum;
    }

    public void setMinimum(Asn1Integer minimum) {
        this.minimum = minimum;
    }

    public Asn1Integer getMaximum() {
        return maximum;
    }

    public void setMaximum(Asn1Integer maximum) {
        this.maximum = maximum;
    }

    public long getMinimumValue() {
        return minimumValue;
    }

    public void setMinimumValue(long minimumValue) {
        this.minimumValue = minimumValue;
    }

    public long getMaximumValue() {
        return maximumValue;
    }

    public void setMaximumValue(long maximumValue) {
        this.maximumValue = maximumValue;
    }

    public boolean isIncludeMinimum() {
        return includeMinimum;
    }

    public void setIncludeMinimum(boolean includeMinimum) {
        this.includeMinimum = includeMinimum;
    }

    public boolean isIncludeMaximum() {
        return includeMaximum;
    }

    public void setIncludeMaximum(boolean includeMaximum) {
        this.includeMaximum = includeMaximum;
    }
}
