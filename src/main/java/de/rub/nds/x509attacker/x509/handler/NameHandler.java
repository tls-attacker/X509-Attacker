/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.handler;

import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.protocol.xml.Pair;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.NameType;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.x509.model.AttributeTypeAndValue;
import de.rub.nds.x509attacker.x509.model.Name;
import de.rub.nds.x509attacker.x509.model.RelativeDistinguishedName;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
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
    public void adjustContext() {
        try {
            LOGGER.debug("Reparsing RDN to update context");
            List<RelativeDistinguishedName> parsedRdnSequence = new LinkedList<>();
            BufferedInputStream rdnByteInputStream = getRdnByteInputStream();
            while (rdnByteInputStream.available() > 0) {
                RelativeDistinguishedName relativeDistinguishedName =
                        new RelativeDistinguishedName("parsedRdn");
                X509Parser parser = relativeDistinguishedName.getParser(chooser);
                parser.parse(rdnByteInputStream);
                parsedRdnSequence.add(relativeDistinguishedName);
            }
            LOGGER.debug("Parsed {} elements", parsedRdnSequence.size());
            LOGGER.debug("Converting parsed RDN to context RDN");
            List<Pair<X500AttributeType, String>> rdnList = new LinkedList<>();
            for (RelativeDistinguishedName parsedRdn : parsedRdnSequence) {
                for (Asn1Encodable encodable : parsedRdn.getChildren()) {
                    if (encodable instanceof AttributeTypeAndValue) {
                        rdnList.add(
                                new Pair<>(
                                        ((AttributeTypeAndValue) encodable)
                                                .getAttributeTypeConfig(),
                                        ((AttributeTypeAndValue) encodable).getValueConfig()));
                    }
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
        } catch (IOException ex) {
            LOGGER.warn("Problem adjusting context");
        }
    }

    private BufferedInputStream getRdnByteInputStream() {
        LOGGER.debug("Creating RdnByteInputStream");
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        for (RelativeDistinguishedName rdnName : component.getRelativeDistinguishedNames()) {
            LOGGER.debug("Adding {}", rdnName.getIdentifier());
            try {
                outputStream.write(rdnName.getSerializer(chooser).serialize());
            } catch (IOException ex) {
                LOGGER.error(ex);
            }
        }
        LOGGER.debug(
                "Serialized RDN Sequence: {}",
                ArrayConverter.bytesToHexString(outputStream.toByteArray()));
        return new BufferedInputStream(new ByteArrayInputStream(outputStream.toByteArray()));
    }
}
