/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser;

import de.rub.nds.asn1.constants.TagClass;
import de.rub.nds.asn1.model.Asn1UnknownField;
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
            LOGGER.debug("Assuming Certificate has a Version field");
            parseVersion(inputStream);
        }
        parseSerialNumber(inputStream);
        parseSignatureInformation(inputStream);
        parseIssuer(inputStream);
        parseValidity(inputStream);
        parseSubject(inputStream);
        parseSubjectPublicKey(inputStream);
        if (hasIssuerUniqueId(inputStream)) {
            LOGGER.debug("Assuming Certificate has an IssuerUniqueID field");
            parseIssuerUniqueId(inputStream);
        }
        if (hasSubjectUniqueId(inputStream)) {
            LOGGER.debug("Assuming Certificate has a SubjectUniqueID field");
            parseSubjectUniqueId(inputStream);
        }
        if (hasExtensions(inputStream)) {
            LOGGER.debug("Assuming Certificate has an Extensions field");
            parseExtensions(inputStream);
        }
    }

    private void parseExtensions(BufferedInputStream inputStream) {
        LOGGER.debug("Parsing Extensions as Unknwon Asn1Field since we did not implement them yet");
        @SuppressWarnings("unused")
        Asn1UnknownField extensions =
                ParserHelper.parseUnknown(inputStream); // TODO not yet implemented
        LOGGER.debug("Extensions are not yet visible in the TbsCertificate");
    }

    private void parseSubjectUniqueId(BufferedInputStream inputStream) {
        ParserHelper.parseAsn1BitString(encodable.getSubjectUniqueId(), inputStream);
        LOGGER.debug(
                "Parsed SubjectUniqueID: {}",
                encodable.getSubjectUniqueId().getUsedBits().getValue());
    }

    private void parseIssuerUniqueId(BufferedInputStream inputStream) {
        ParserHelper.parseAsn1BitString(encodable.getIssuerUniqueId(), inputStream);
        LOGGER.debug(
                "Parsed IssuerUniqueID: {}",
                encodable.getSubjectUniqueId().getUsedBits().getValue());
    }

    private boolean hasVersionField(BufferedInputStream inputStream) {
        return ParserHelper.canParse(inputStream, TagClass.CONTEXT_SPECIFIC, 0);
    }

    private boolean hasExtensions(BufferedInputStream inputStream) {
        return ParserHelper.canParse(inputStream, TagClass.CONTEXT_SPECIFIC, 3);
    }

    private boolean hasSubjectUniqueId(BufferedInputStream inputStream) {
        return ParserHelper.canParse(inputStream, TagClass.CONTEXT_SPECIFIC, 2);
    }

    private boolean hasIssuerUniqueId(BufferedInputStream inputStream) {
        return ParserHelper.canParse(inputStream, TagClass.CONTEXT_SPECIFIC, 1);
    }

    private void parseSubjectPublicKey(BufferedInputStream inputStream) {
        encodable.getSubjectPublicKeyInfo().getParser(chooser).parse(inputStream);
        encodable.getSubjectPublicKeyInfo().getHandler(chooser).adjustContextAfterParse();
    }

    private void parseSubject(BufferedInputStream inputStream) {
        encodable.getSubject().getParser(chooser).parse(inputStream);
        encodable.getSubject().getHandler(chooser).adjustContextAfterParse();
    }

    private void parseValidity(BufferedInputStream inputStream) {
        encodable.getValidity().getParser(chooser).parse(inputStream);
        encodable.getValidity().getHandler(chooser).adjustContextAfterParse();
    }

    private void parseIssuer(BufferedInputStream inputStream) {
        encodable.getIssuer().getParser(chooser).parse(inputStream);
        encodable.getIssuer().getHandler(chooser).adjustContextAfterParse();
    }

    private void parseSignatureInformation(BufferedInputStream inputStream) {
        encodable.getSignature().getParser(chooser).parse(inputStream);
        encodable.getSignature().getHandler(chooser).adjustContextAfterParse();
    }

    private void parseSerialNumber(BufferedInputStream inputStream) {
        ParserHelper.parseAsn1Integer(encodable.getSerialNumber(), inputStream);
        LOGGER.debug("Parsed SerialNumber: {}", encodable.getSerialNumber().getValue());
    }

    private void parseVersion(BufferedInputStream inputStream) {
        encodable.getVersion().getParser(chooser).parse(inputStream);
        encodable.getVersion().getHandler(chooser).adjustContextAfterParse();
        LOGGER.debug(
                "Parsed Version: {}", encodable.getVersion().getInnerField().getValue().getValue());
    }
}
