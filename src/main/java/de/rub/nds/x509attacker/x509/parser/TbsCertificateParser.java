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
import de.rub.nds.asn1.parser.ParserHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.Extensions;
import de.rub.nds.x509attacker.x509.model.TbsCertificate;
import de.rub.nds.x509attacker.x509.model.X509Explicit;
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
        } else {
            encodable.setVersion(null);
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
        } else {
            encodable.setIssuerUniqueId(null);
        }
        if (hasSubjectUniqueId(inputStream)) {
            LOGGER.debug("Assuming Certificate has a SubjectUniqueID field");
            parseSubjectUniqueId(inputStream);
        } else {
            encodable.setSubjectUniqueId(null);
        }
        if (hasExtensions(inputStream)) {
            LOGGER.debug("Assuming Certificate has an Extensions field");
            parseExtensions(inputStream);
        } else {
            encodable.setExplicitExtensions(null);
        }
    }

    private void parseExtensions(BufferedInputStream inputStream) {
        encodable.getExplicitExtensions().getParser(chooser).parse(inputStream);
        encodable.getExplicitExtensions().getHandler(chooser).adjustContextAfterParse();
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
