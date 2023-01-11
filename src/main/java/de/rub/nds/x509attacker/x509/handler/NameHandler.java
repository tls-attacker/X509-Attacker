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
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.NameType;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.x509.base.AttributeTypeAndValue;
import de.rub.nds.x509attacker.x509.base.Name;
import de.rub.nds.x509attacker.x509.base.RelativeDistinguishedName;
import de.rub.nds.x509attacker.x509.parser.RelativeDistinguishedNameParser;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** The Subject of a Certificate becomes the issuer of the next certificate */
public class NameHandler extends X509Handler {

    private static final Logger LOGGER = LogManager.getLogger();

    private Name name;

    public NameHandler(X509Chooser chooser, Name name) {
        super(chooser);
        this.name = name;
    }

    @Override
    public void adjustContext() {
        try {
            LOGGER.debug("Reparsing RDN to update context");
            List<RelativeDistinguishedName> parsedRdnSequence = new LinkedList<>();
            InputStream rdnByteInputStream = getRdnByteInputStream();
            while (rdnByteInputStream.available() > 0) {
                RelativeDistinguishedName relativeDistinguishedName =
                        new RelativeDistinguishedName("parsedRdn");
                RelativeDistinguishedNameParser parser =
                        relativeDistinguishedName.getParser(chooser);
                parser.parseTagOctets(rdnByteInputStream);
                byte[] lengthBytes = parser.parseLengthOctets(rdnByteInputStream);
                BigInteger length = parser.parseLength(lengthBytes);
                parser.parseIndividualContentFields(
                        new ByteArrayInputStream(rdnByteInputStream.readNBytes(length.intValue())));
            }
            List<Pair<X500AttributeType, String>> rdnList = new LinkedList<>();
            for (RelativeDistinguishedName parsedRdn : parsedRdnSequence) {
                for (Asn1Encodable encodable : parsedRdn.getChildren()) {
                    if (encodable instanceof AttributeTypeAndValue) {
                        rdnList.add(
                                new ImmutablePair<>(
                                        ((AttributeTypeAndValue) encodable)
                                                .getAttributeTypeConfig(),
                                        ((AttributeTypeAndValue) encodable).getValueConfig()));
                    }
                }
            }
            if (name.getType() == NameType.ISSUER) {
                context.setIssuer(rdnList);
            } else if (name.getType() == NameType.SUBJECT) {
                context.setIssuer(rdnList);
            } else {
                throw new RuntimeException("Unknown NameType: " + name.getType().name());
            }
            chooser.getContext().setIssuer(rdnList);
        } catch (IOException ex) {
            LOGGER.warn("Problem adjusting context");
        }
    }

    private InputStream getRdnByteInputStream() {
        LOGGER.debug("Creating RdnByteInputStream");
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        for (RelativeDistinguishedName rdnName : name.getRelativeDistinguishedNames()) {
            LOGGER.debug("Adding {}", rdnName.getIdentifier());
            try {
                outputStream.write(rdnName.getSerializer().serialize());
            } catch (IOException ex) {
                LOGGER.error(ex);
            }
        }
        LOGGER.debug(
                "Serialized RDN Sequence: {}",
                ArrayConverter.bytesToHexString(outputStream.toByteArray()));
        return new ByteArrayInputStream(outputStream.toByteArray());
    }
}
