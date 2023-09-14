/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser;

import de.rub.nds.asn1.constants.TagClass;
import de.rub.nds.asn1.parser.ParserHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.EdiPartyName;
import java.io.BufferedInputStream;

public class EdiPartyNameParser extends X509ComponentContainerParser<EdiPartyName> {

    private static final int EXPLICIT_TAG_NUMBER = 0;

    public EdiPartyNameParser(X509Chooser chooser, EdiPartyName ediPartyName) {
        super(chooser, ediPartyName);
    }

    @Override
    protected void parseSubcomponents(BufferedInputStream inputStream) {
        if (ParserHelper.canParse(inputStream, TagClass.CONTEXT_SPECIFIC, EXPLICIT_TAG_NUMBER)) {
            encodable.getNameAssigner().getParser(chooser).parse(inputStream);
        }
        encodable.getPartyName().getParser(chooser).parse(inputStream);
    }
}
