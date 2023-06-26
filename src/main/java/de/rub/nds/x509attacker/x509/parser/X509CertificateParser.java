/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser;

import de.rub.nds.asn1.parser.ParserHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import java.io.BufferedInputStream;

public class X509CertificateParser extends X509ComponentContainerParser<X509Certificate> {

    public X509CertificateParser(X509Chooser chooser, X509Certificate x509Certificate) {
        super(chooser, x509Certificate);
    }

    @Override
    protected void parseSubcomponents(BufferedInputStream inputStream) {
        encodable.getTbsCertificate().getParser(chooser).parse(inputStream);
        encodable.getSignatureAlgorithmIdentifier().getParser(chooser).parse(inputStream);
        ParserHelper.parseAsn1BitString(encodable.getSignature(), inputStream);
    }
}
