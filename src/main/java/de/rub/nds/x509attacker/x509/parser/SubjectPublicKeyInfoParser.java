/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser;

import java.io.InputStream;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.asn1.model.Asn1Field;
import de.rub.nds.asn1.parser.Asn1FieldParser;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.SubjectPublicKeyInfo;
import de.rub.nds.x509attacker.x509.base.publickey.parameters.X509DhParameters;
import de.rub.nds.x509attacker.x509.base.publickey.parameters.X509EcNamedCurveParameters;

public class SubjectPublicKeyInfoParser extends Asn1FieldParser<SubjectPublicKeyInfo> implements X509Parser {

    private static final Logger LOGGER = LogManager.getLogger();

    private final X509Chooser chooser;

    public SubjectPublicKeyInfoParser(X509Chooser chooser, SubjectPublicKeyInfo field) {
        super(field);
        this.chooser = chooser;
    }

    @Override
    public void parse(InputStream inputStream) {
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
