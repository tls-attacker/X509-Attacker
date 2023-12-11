/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser;

import de.rub.nds.asn1.parser.ParserHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import java.io.BufferedInputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class X509CertificateParser extends X509ComponentContainerParser<X509Certificate> {

    private static final Logger LOGGER = LogManager.getLogger();

    public X509CertificateParser(X509Chooser chooser, X509Certificate x509Certificate) {
        super(chooser, x509Certificate);
    }

    @Override
    protected void parseSubcomponents(BufferedInputStream inputStream) {
        LOGGER.debug("Parsing X509Certificate");
        parseTbsCertificate(inputStream);
        parseSignatureAlgorithmIdentifier(inputStream);
        parseSignature(inputStream);
    }

    private void parseSignature(BufferedInputStream inputStream) {
        ParserHelper.parseAsn1BitString(encodable.getSignature(), inputStream);
        LOGGER.debug("Parsed Signature: {}", encodable.getSignature().getUsedBits().getValue());
    }

    private void parseSignatureAlgorithmIdentifier(BufferedInputStream inputStream) {
        encodable.getSignatureAlgorithmIdentifier().getParser(chooser).parse(inputStream);
        encodable.getSignatureAlgorithmIdentifier().getHandler(chooser).adjustContextAfterParse();
        LOGGER.debug(
                "Parsed SignatureAlgorithmIdentifier: {}",
                encodable.getSignatureAlgorithmIdentifier().getAlgorithm().getValue().getValue());
    }

    private void parseTbsCertificate(BufferedInputStream inputStream) {
        encodable.getTbsCertificate().getParser(chooser).parse(inputStream);
        encodable.getTbsCertificate().getHandler(chooser).adjustContextAfterParse();
        LOGGER.debug("Parsed TbsCertificate");
    }
}
