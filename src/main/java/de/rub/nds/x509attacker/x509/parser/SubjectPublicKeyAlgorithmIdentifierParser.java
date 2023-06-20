/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser;

import de.rub.nds.asn1.model.Asn1Null;
import de.rub.nds.asn1.parser.ParserHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.x509.model.SubjectPublicKeyAlgorithmIdentifier;
import de.rub.nds.x509attacker.x509.model.publickey.parameters.PublicParameters;
import de.rub.nds.x509attacker.x509.model.publickey.parameters.X509DhParameters;
import de.rub.nds.x509attacker.x509.model.publickey.parameters.X509EcNamedCurveParameters;
import java.io.PushbackInputStream;

public class SubjectPublicKeyAlgorithmIdentifierParser
        extends X509ComponentContainerParser<SubjectPublicKeyAlgorithmIdentifier> {

    public SubjectPublicKeyAlgorithmIdentifierParser(
            X509Chooser chooser, SubjectPublicKeyAlgorithmIdentifier algorithmIdentifier) {
        super(chooser, algorithmIdentifier);
    }

    @Override
    protected void parseSubcomponents(PushbackInputStream inputStream) {
        ParserHelper.parseAsn1ObjectIdentifier(encodable.getAlgorithm(), inputStream);
        PublicParameters parameters;
        switch (X509PublicKeyType.decodeFromOidBytes(
                encodable.getAlgorithm().getValueAsOid().getEncoded())) {
            case ECDH_ECDSA:
                parameters = new X509EcNamedCurveParameters("EcNamedCurveParameters");
                parameters.getParser(chooser).parse(inputStream);
                break;
            case DH:
                parameters = new X509DhParameters("DhParameters");
                break;
            default:
                parameters = null;
                break;
        }
        if (parameters == null) {
            Asn1Null nullField = new Asn1Null("null");
            encodable.setParameters(nullField);
            ParserHelper.parseAsn1Null(nullField, inputStream);
        } else {
            encodable.setParameters(parameters);
        }
    }
}
