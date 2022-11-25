/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser;

import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1Set;
import de.rub.nds.asn1.parser.Asn1SetParser;
import de.rub.nds.x509attacker.x509.base.AttributeTypeAndValue;

public class RelativeDistinguishedNameParser extends Asn1SetParser {

    public RelativeDistinguishedNameParser(Asn1Set asn1Set) {
        super(asn1Set);
    }

    @Override
    protected Asn1Encodable createFreshElement() {
        return new AttributeTypeAndValue("element");
    }
}
