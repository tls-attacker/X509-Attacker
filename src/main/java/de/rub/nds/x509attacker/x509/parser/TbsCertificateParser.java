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

public class TbsCertificateParser extends X509ComponentContainerParser<TbsCertificate> {

    public TbsCertificateParser(X509Chooser chooser, TbsCertificate tbsCertificate) {
        super(chooser, tbsCertificate);
    }

    @Override
    protected void parseSubcomponents(BufferedInputStream inputStream) {
        encodable.getVersion().getParser(chooser).parse(inputStream);
        ParserHelper.parseAsn1Integer(encodable.getSerialNumber(), inputStream);
        encodable.getSignature().getParser(chooser).parse(inputStream);
        encodable.getIssuer().getParser(chooser).parse(inputStream);
        encodable.getValidity().getParser(chooser).parse(inputStream);
        encodable.getSubjectPublicKeyInfo().getParser(chooser).parse(inputStream);
        if (ParserHelper.canParse(inputStream, TagClass.CONTEXT_SPECIFIC, 1)) {
            ParserHelper.parseAsn1BitString(encodable.getIssuerUniqueId(), inputStream);
        }
        if (ParserHelper.canParse(inputStream, TagClass.CONTEXT_SPECIFIC, 2)) {
            ParserHelper.parseAsn1BitString(encodable.getSubjectUniqueId(), inputStream);
        }
        if (ParserHelper.canParse(inputStream, TagClass.CONTEXT_SPECIFIC, 3)) {
            encodable.getExplicitExtensions().getParser(chooser).parse(inputStream);
        }
    }
}
