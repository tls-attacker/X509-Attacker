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
import de.rub.nds.asn1.parser.Asn1SequenceOfParser;
import de.rub.nds.x509attacker.x509.base.Extension;
import de.rub.nds.x509attacker.x509.base.Extensions;

public class ExtensionsParser extends Asn1SequenceOfParser {

    public ExtensionsParser(Extensions extensions) {
        super(extensions);
    }

    @Override
    protected Asn1Encodable createFreshElement() {
        return new Extension("extension");
    }
}
