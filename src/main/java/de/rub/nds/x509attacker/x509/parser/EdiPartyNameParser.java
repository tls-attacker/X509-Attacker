/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser;

import de.rub.nds.asn1.constants.TagClass;
import de.rub.nds.asn1.parser.ParserHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.EdiPartyName;
import java.io.PushbackInputStream;

public class EdiPartyNameParser extends X509ComponentContainerParser<EdiPartyName> {

    public EdiPartyNameParser(X509Chooser chooser, EdiPartyName ediPartyName) {
        super(chooser, ediPartyName);
    }

    @Override
    protected void parseSubcomponents(PushbackInputStream inputStream) {
        if(ParserHelper.canParse(inputStream, TagClass.CONTEXT_SPECIFIC, 0)){
            encodable.getNameAssigner().getParser(chooser).parse(inputStream);
        }
        encodable.getPartyName().getParser(chooser).parse(inputStream);
    }
}
