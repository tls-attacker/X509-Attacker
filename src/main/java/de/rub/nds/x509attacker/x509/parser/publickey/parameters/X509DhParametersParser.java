/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser.publickey.parameters;

import de.rub.nds.asn1.constants.TagClass;
import de.rub.nds.asn1.constants.UniversalTagNumber;
import de.rub.nds.asn1.parser.ParserHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.publickey.parameters.X509DhParameters;
import de.rub.nds.x509attacker.x509.parser.X509ComponentContainerParser;
import java.io.BufferedInputStream;

public class X509DhParametersParser extends X509ComponentContainerParser<X509DhParameters> {

    public X509DhParametersParser(X509Chooser chooser, X509DhParameters x509DhParameters) {
        super(chooser, x509DhParameters);
    }

    @Override
    protected void parseSubcomponents(BufferedInputStream inputStream) {
        ParserHelper.parseAsn1Integer(encodable.getP(), inputStream);
        ParserHelper.parseAsn1Integer(encodable.getG(), inputStream);
        ParserHelper.parseAsn1Integer(encodable.getQ(), inputStream);
        if (ParserHelper.canParse(
                inputStream, TagClass.UNIVERSAL, UniversalTagNumber.INTEGER.getIntValue())) {
            ParserHelper.parseAsn1Integer(encodable.getP(), inputStream);
        }
        if (ParserHelper.canParse(
                inputStream, TagClass.UNIVERSAL, UniversalTagNumber.SEQUENCE.getIntValue())) {
            encodable.getValidationParms().getParser(chooser).parse(inputStream);
        }
    }
}
