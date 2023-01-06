/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser;

import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.parser.Asn1SequenceOfParser;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.RelativeDistinguishedName;

public class NameParser extends Asn1SequenceOfParser<X509Chooser> {

    public NameParser(X509Chooser chooser, Asn1Sequence asn1Sequence) {
        super(chooser, asn1Sequence);
    }

    @Override
    protected Asn1Encodable createFreshElement() {
        return new RelativeDistinguishedName("rdn");
    }
}
