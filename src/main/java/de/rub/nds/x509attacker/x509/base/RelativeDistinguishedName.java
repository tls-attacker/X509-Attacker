/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.asn1.handler.Handler;
import de.rub.nds.asn1.model.Asn1Set;
import de.rub.nds.protocol.xml.Pair;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.x509.parser.RelativeDistinguishedNameParser;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.List;

/** RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class RelativeDistinguishedName extends Asn1Set<X509Chooser> {

    private RelativeDistinguishedName() {
        super(null);
    }

    public RelativeDistinguishedName(String identifier) {
        super(identifier);
    }

    public RelativeDistinguishedName(
            String identifier, List<Pair<X500AttributeType, String>> attributeList) {
        super(identifier);
        for (Pair<X500AttributeType, String> pair : attributeList) {
            AttributeTypeAndValue attributeTypeAndValue =
                    new AttributeTypeAndValue(
                            pair.getKey()
                                    .getHumanReadableName()
                                    .concat("=")
                                    .concat(pair.getValue()),
                            pair.getKey(),
                            pair.getValue());
            addChild(attributeTypeAndValue);
        }
    }

    public RelativeDistinguishedName(
            String identifier, Pair<X500AttributeType, String>... attributes) {
        super(identifier);
        for (Pair<X500AttributeType, String> pair : attributes) {
            AttributeTypeAndValue attributeTypeAndValue =
                    new AttributeTypeAndValue(
                            pair.getKey()
                                    .getHumanReadableName()
                                    .concat("=")
                                    .concat(pair.getValue()),
                            pair.getKey(),
                            pair.getValue());
            addChild(attributeTypeAndValue);
        }
    }

    @Override
    public RelativeDistinguishedNameParser getParser(X509Chooser chooser) {
        return new RelativeDistinguishedNameParser(chooser, this);
    }

    @Override
    public Handler<X509Chooser> getHandler(X509Chooser chooser) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
