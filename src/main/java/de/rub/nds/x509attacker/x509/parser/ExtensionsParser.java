/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser;

import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.oid.ObjectIdentifier;
import de.rub.nds.asn1.parser.ParserHelper;
import de.rub.nds.protocol.exception.ParserException;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.X509ExtensionType;
import de.rub.nds.x509attacker.x509.model.Extension;
import de.rub.nds.x509attacker.x509.model.Extensions;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.BufferedInputStream;
import java.io.IOException;

public class ExtensionsParser extends X509ComponentContainerParser<Extensions> {

    private final Logger LOGGER = LogManager.getLogger();

    public ExtensionsParser(X509Chooser chooser, Extensions extensions) {
        super(chooser, extensions);
    }

    @Override
    protected void parseSubcomponents(BufferedInputStream inputStream) {
        LOGGER.debug("Parsing Extensions");
        try {
            while (inputStream.available() > 0) {
                LOGGER.debug("Parsing Extension");
                // peek at oid in stream and parse correct extension
                Extension extension = X509ExtensionType.decodeFromOidBytes(
                        peekNextObjectIdentifier(inputStream).getEncoded()
                ).generateExtension();
                extension.getParser(chooser).parse(inputStream);
                extension.getHandler(chooser).adjustContextAfterParse();
                encodable.addExtension(extension);
            }
        } catch (IOException E) {
            throw new ParserException("IOException in RelativeDistinguishedNameParser", E);
        }
    }

    /**
     * Peeks at the OID of the next extension in the list. Allows to choose the correct extension parser.
     * @param inputStream Contains remaining certificate bytes
     * @return ObjectIdentifier
     */
    private ObjectIdentifier peekNextObjectIdentifier(BufferedInputStream inputStream) {
        try {
            Asn1ObjectIdentifier oid = new Asn1ObjectIdentifier("oid");
            inputStream.mark(inputStream.available());
            // parse extension structure header
            ParserHelper.parseStructure(new Extension("extension"), inputStream);
            // parse OID
            X509Asn1ObjectIdentifierParser oidParser = new X509Asn1ObjectIdentifierParser(chooser, oid);
            oidParser.parse(inputStream);
            inputStream.reset();
            return oid.getValueAsOid();
        } catch (IOException e) {
            throw new ParserException("Could not look ahead to next extension OID.");
        }
    }
}
