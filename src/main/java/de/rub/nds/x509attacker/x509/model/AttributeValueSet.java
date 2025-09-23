/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model;

import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1Set;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.AttributeValueSetPreparator;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAnyElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.List;

/** values SET OF AttributeValue */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class AttributeValueSet extends Asn1Set implements X509Component {

    @HoldsModifiableVariable
    @XmlAnyElement(lax = true)
    private List<Asn1Encodable> valueHolders;

    @HoldsModifiableVariable private List<String> values;

    private AttributeValueSet() {
        super(null);
    }

    public AttributeValueSet(String identifier) {
        super(identifier);
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
        return new AttributeValueSetPreparator(chooser, this);
    }

    public List<Asn1Encodable> getValueHolders() {
        return valueHolders;
    }

    public void setValueHolders(List<Asn1Encodable> valueHolders) {
        this.valueHolders = valueHolders;
    }

    public List<String> getValues() {
        return values;
    }

    public void setValues(List<String> values) {
        this.values = values;
    }
}
