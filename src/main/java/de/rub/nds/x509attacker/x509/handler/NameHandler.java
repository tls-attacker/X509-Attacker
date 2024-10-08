/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.handler;

import de.rub.nds.protocol.xml.Pair;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.NameType;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.x509.model.AttributeTypeAndValue;
import de.rub.nds.x509attacker.x509.model.Name;
import de.rub.nds.x509attacker.x509.model.RelativeDistinguishedName;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** The Subject of a Certificate becomes the issuer of the next certificate */
public class NameHandler extends X509FieldHandler<Name> {

    private static final Logger LOGGER = LogManager.getLogger();

    public NameHandler(X509Chooser chooser, Name name) {
        super(chooser, name);
    }

    @Override
    public void adjustContextAfterParse() {
        adjustContext();
    }

    @Override
    public void adjustContextAfterPrepare() {
        adjustContext();
    }

    public void adjustContext() {
        LOGGER.debug("Converting RDN to context RDN");
        List<Pair<X500AttributeType, String>> rdnList = new LinkedList<>();
        for (RelativeDistinguishedName parsedRdn : component.getRelativeDistinguishedNames()) {
            for (AttributeTypeAndValue attributeTypeAndValue :
                    parsedRdn.getAttributeTypeAndValueList()) {
                rdnList.add(
                        new Pair<>(
                                attributeTypeAndValue.getAttributeTypeConfig(),
                                attributeTypeAndValue.getValueConfig()));
            }
        }
        LOGGER.debug("Converted into {} elements", rdnList.size());
        if (component.getType() == NameType.ISSUER) {
            context.setIssuer(rdnList);
        } else if (component.getType() == NameType.SUBJECT) {
            context.setSubject(rdnList);
        } else {
            throw new RuntimeException("Unknown NameType: " + component.getType().name());
        }
    }
}
