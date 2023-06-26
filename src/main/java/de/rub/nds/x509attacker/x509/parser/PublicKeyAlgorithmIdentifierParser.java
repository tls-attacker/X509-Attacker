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
import de.rub.nds.x509attacker.x509.model.SubjectPublicKeyAlgorithmIdentifier;
import java.io.BufferedInputStream;

public class PublicKeyAlgorithmIdentifierParser
        extends X509ComponentContainerParser<SubjectPublicKeyAlgorithmIdentifier> {

    public PublicKeyAlgorithmIdentifierParser(
            X509Chooser chooser, SubjectPublicKeyAlgorithmIdentifier encodable) {
        super(chooser, encodable);
    }

    @Override
    protected void parseSubcomponents(BufferedInputStream inputStream) {
        ParserHelper.parseAsn1ObjectIdentifier(encodable.getAlgorithm(), inputStream);
        encodable.setParameters(ParserHelper.parseUnknown(inputStream));
    }
}
