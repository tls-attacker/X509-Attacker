/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser;

import de.rub.nds.asn1.constants.TagClass;
import de.rub.nds.asn1.parser.ParserHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.TbsCertificate;
import java.io.BufferedInputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class TbsCertificateParser extends X509ComponentContainerParser<TbsCertificate> {

    private static final Logger LOGGER = LogManager.getLogger();

    public TbsCertificateParser(X509Chooser chooser, TbsCertificate tbsCertificate) {
        super(chooser, tbsCertificate);
    }

    @Override
    protected void parseSubcomponents(BufferedInputStream inputStream) {
        if (hasVersionField(inputStream)) {
            parseVersion(inputStream);
        }
        parseSerialNumber(inputStream);
        parseSignatureInformation(inputStream);
        parseIssuer(inputStream);
        parseValidity(inputStream);
        parseSubject(inputStream);
        parseSubjectPublicKey(inputStream);
        if (hasIssuerUniqueId(inputStream)) {
            parseIssuerUniqueId(inputStream);
        }
        if (hasSubjectUniqueId(inputStream)) {
            parseSubjectUniqueId(inputStream);
        }
        if (hasExtensions(inputStream)) {
            parseExtensions(inputStream);
        }
    }

    private void parseExtensions(BufferedInputStream inputStream) {
        LOGGER.debug("Parsing Extensions");
        ParserHelper.parseUnknown(inputStream); // TODO not yet implemented
        // encodable.getExplicitExtensions().getParser(chooser).parse(inputStream);
    }

    private void parseSubjectUniqueId(BufferedInputStream inputStream) {
        LOGGER.debug("Parsing extensions");
        ParserHelper.parseAsn1BitString(encodable.getSubjectUniqueId(), inputStream);
        LOGGER.debug("Finished parsing extensions");
    }

    private void parseIssuerUniqueId(BufferedInputStream inputStream) {
        LOGGER.debug("Parsing issuer unique id");
        ParserHelper.parseAsn1BitString(encodable.getIssuerUniqueId(), inputStream);
        LOGGER.debug("Finished parsing issuer unique id");
    }

    private boolean hasVersionField(BufferedInputStream inputStream) {
        LOGGER.debug("Checking if Version can be parsed");
        return ParserHelper.canParse(inputStream, TagClass.CONTEXT_SPECIFIC, 0);
    }

    private boolean hasExtensions(BufferedInputStream inputStream) {
        LOGGER.debug("Checking if tbsCertificate contains extensions");
        return ParserHelper.canParse(inputStream, TagClass.CONTEXT_SPECIFIC, 3);
    }

    private boolean hasSubjectUniqueId(BufferedInputStream inputStream) {
        LOGGER.debug("Checking if tbsCertificate contains subject unique id");
        return ParserHelper.canParse(inputStream, TagClass.CONTEXT_SPECIFIC, 2);
    }

    private boolean hasIssuerUniqueId(BufferedInputStream inputStream) {
        LOGGER.debug("Checking if tbsCertificate contains issuer unique id");
        return ParserHelper.canParse(inputStream, TagClass.CONTEXT_SPECIFIC, 1);
    }

    private void parseSubjectPublicKey(BufferedInputStream inputStream) {
        LOGGER.debug("Parsing subject public key info");
        encodable.getSubjectPublicKeyInfo().getParser(chooser).parse(inputStream);
        LOGGER.debug("Finished parsing subject public key");
    }

    private void parseSubject(BufferedInputStream inputStream) {
        LOGGER.debug("Parsing subject");
        encodable.getSubject().getParser(chooser).parse(inputStream);
        LOGGER.debug("Finished parsing subject");
    }

    private void parseValidity(BufferedInputStream inputStream) {
        LOGGER.debug("Parsing validity");
        encodable.getValidity().getParser(chooser).parse(inputStream);
        LOGGER.debug("Finished parsing validity");
    }

    private void parseIssuer(BufferedInputStream inputStream) {
        LOGGER.debug("Parsing issuer");
        encodable.getIssuer().getParser(chooser).parse(inputStream);
        LOGGER.debug("Finished parsing issuer");
    }

    private void parseSignatureInformation(BufferedInputStream inputStream) {
        LOGGER.debug("Parsing signature information");
        encodable.getSignature().getParser(chooser).parse(inputStream);
        LOGGER.debug("Finished parsing signature information");
    }

    private void parseSerialNumber(BufferedInputStream inputStream) {
        LOGGER.debug("Parsing serial number");
        ParserHelper.parseAsn1Integer(encodable.getSerialNumber(), inputStream);
        LOGGER.debug("Finished parsing serial number");
    }

    private void parseVersion(BufferedInputStream inputStream) {
        LOGGER.debug("Parsing version");
        encodable.getVersion().getParser(chooser).parse(inputStream);
        LOGGER.debug("Finished parsing version");
    }
}
