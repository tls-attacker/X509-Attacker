/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser;

import de.rub.nds.asn1.model.Asn1Field;
import de.rub.nds.asn1.parser.Asn1SequenceParser;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.SubjectPublicKeyInfo;
import de.rub.nds.x509attacker.x509.base.publickey.parameters.X509DhParameters;
import de.rub.nds.x509attacker.x509.base.publickey.parameters.X509EcNamedCurveParameters;
import java.io.IOException;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SubjectPublicKeyInfoParser extends Asn1SequenceParser<X509Chooser> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SubjectPublicKeyInfoParser(X509Chooser chooser, SubjectPublicKeyInfo field) {
        super(chooser, field);
    }

    @Override
    public void parseIndividualContentFields(InputStream inputStream) throws IOException {
        super.parseIndividualContentFields(inputStream);
    }

    @Override
    protected Asn1Field chooseInstantiationForAny() {
        switch (chooser.getSubjectPublicKeyType()) {
            case ECDH_ECDSA:
                LOGGER.debug("Predicted EcNamedCurveParameters");
                return new X509EcNamedCurveParameters("EcNamedCurveParameters");
            case DH:
                LOGGER.debug("Predicted DhParameters");
                return new X509DhParameters("DhParameters");
            default:
                return null;
        }
    }
}
