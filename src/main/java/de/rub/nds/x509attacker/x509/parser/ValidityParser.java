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
import de.rub.nds.asn1.constants.UniversalTagNumber;
import de.rub.nds.asn1.time.TimeField;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.Validity;
import java.io.PushbackInputStream;

public class ValidityParser extends X509ComponentContainerParser<Validity> {

    public ValidityParser(X509Chooser chooser, Validity validity) {
        super(chooser, validity);
    }

    @Override
    protected void parseSubcomponents(PushbackInputStream inputStream) {
        encodable.setNotBefore(
                (TimeField)
                        Asn1ParserHelper.parseTagNumberField(
                                inputStream,
                                TagClass.UNIVERSAL,
                                UniversalTagNumber.GENERALIZEDTIME,
                                UniversalTagNumber.UTCTIME));
        encodable.setNotAfter(
                (TimeField)
                        Asn1ParserHelper.parseTagNumberField(
                                inputStream,
                                TagClass.UNIVERSAL,
                                UniversalTagNumber.GENERALIZEDTIME,
                                UniversalTagNumber.UTCTIME));
    }
}
