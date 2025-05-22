/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser.extension;

import de.rub.nds.asn1.constants.TagClass;
import de.rub.nds.asn1.parser.ParserHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.extensions.AuthorityKeyIdentifier;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;

public class AuthorityKeyIdentifierParser extends ExtensionParser<AuthorityKeyIdentifier> {
    public AuthorityKeyIdentifierParser(X509Chooser chooser, AuthorityKeyIdentifier extension) {
        super(chooser, extension);
    }

    @Override
    void parseExtensionContent(BufferedInputStream inputStream) {
        ParserHelper.parseStructure(encodable.getWrappingSequence(), inputStream);
        BufferedInputStream contentStream =
                new BufferedInputStream(
                        new ByteArrayInputStream(
                                encodable.getWrappingSequence().getContent().getValue()));

        if (hasKeyIdentifierField(contentStream)) {
            parseKeyIdentifier(contentStream);
        }

        if (hasAuthorityCertIssuerField(contentStream)) {
            parseAuthorityCertIssuer(contentStream);
        }

        if (hasAuthorityCertSerialNumberField(contentStream)) {
            parseAuthorityCertSerialNumber(contentStream);
        }
    }

    private void parseKeyIdentifier(BufferedInputStream inputStream) {
        ParserHelper.parseStructure(encodable.getKeyIdentifier(), inputStream);
    }

    private void parseAuthorityCertIssuer(BufferedInputStream inputStream) {
        // TODO: GeneralNames parser
    }

    private void parseAuthorityCertSerialNumber(BufferedInputStream inputStream) {
        ParserHelper.parseAsn1Integer(encodable.getAuthorityCertSerialNumber(), inputStream);
    }

    private boolean hasKeyIdentifierField(BufferedInputStream inputStream) {
        return ParserHelper.canParse(inputStream, TagClass.CONTEXT_SPECIFIC, 1);
    }

    private boolean hasAuthorityCertIssuerField(BufferedInputStream inputStream) {
        return ParserHelper.canParse(inputStream, TagClass.CONTEXT_SPECIFIC, 2);
    }

    private boolean hasAuthorityCertSerialNumberField(BufferedInputStream inputStream) {
        return ParserHelper.canParse(inputStream, TagClass.CONTEXT_SPECIFIC, 3);
    }
}
