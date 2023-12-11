/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser.publickey;

import de.rub.nds.asn1.parser.ParserHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.publickey.X509RsaPublicKey;
import de.rub.nds.x509attacker.x509.parser.X509ComponentContainerParser;
import java.io.BufferedInputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class X509RsaPublicKeyParser extends X509ComponentContainerParser<X509RsaPublicKey> {

    private static final Logger LOGGER = LogManager.getLogger();

    public X509RsaPublicKeyParser(X509Chooser chooser, X509RsaPublicKey rsaPublicKey) {
        super(chooser, rsaPublicKey);
    }

    @Override
    protected void parseSubcomponents(BufferedInputStream inputStream) {
        LOGGER.debug("Parsing X509RsaPublicKey");
        parseModulus(inputStream);
        parsePublicExponent(inputStream);
    }

    private void parseModulus(BufferedInputStream inputStream) {
        ParserHelper.parseAsn1Integer(encodable.getModulus(), inputStream);
        LOGGER.debug("Parsed Modulus (N): {}", encodable.getModulus().getValue().getValue());
    }

    private void parsePublicExponent(BufferedInputStream inputStream) {
        ParserHelper.parseAsn1Integer(encodable.getPublicExponent(), inputStream);
        LOGGER.debug(
                "Parsed Public exponent (e): {}",
                encodable.getPublicExponent().getValue().getValue());
    }
}
