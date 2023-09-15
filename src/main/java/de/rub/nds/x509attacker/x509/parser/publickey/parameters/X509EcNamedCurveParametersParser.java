/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser.publickey.parameters;

import de.rub.nds.asn1.parser.ParserHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.X509NamedCurve;
import de.rub.nds.x509attacker.x509.model.publickey.parameters.X509EcNamedCurveParameters;
import de.rub.nds.x509attacker.x509.parser.X509ComponentParser;
import java.io.BufferedInputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class X509EcNamedCurveParametersParser
        extends X509ComponentParser<X509EcNamedCurveParameters> {

    private static final Logger LOGGER = LogManager.getLogger();

    public X509EcNamedCurveParametersParser(
            X509Chooser chooser, X509EcNamedCurveParameters x509EcNamedCurveParameters) {
        super(chooser, x509EcNamedCurveParameters);
    }

    @Override
    public void parse(BufferedInputStream inputStream) {
        LOGGER.debug("Parsing X509EcNamedCurveParameters");
        ParserHelper.parseAsn1ObjectIdentifier(encodable, inputStream);
        X509NamedCurve namedCurve =
                X509NamedCurve.decodeFromOidBytes(encodable.getValueAsOid().getEncoded());
        LOGGER.debug(
                "Parsed ObjectIdentidifier: {} ({})",
                encodable.getValue().getValue(),
                namedCurve == null ? "unknown" : namedCurve.name());
    }
}
