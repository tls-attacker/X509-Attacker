/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser.extension;

import de.rub.nds.asn1.model.Asn1BitString;
import de.rub.nds.asn1.parser.ParserHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.extensions.KeyUsage;
import java.io.BufferedInputStream;

public class KeyUsageParser extends ExtensionParser<KeyUsage> {
    public KeyUsageParser(X509Chooser chooser, KeyUsage extension) {
        super(chooser, extension);
    }

    @Override
    void parseExtensionContent(BufferedInputStream inputStream) {
        Asn1BitString bitString = new Asn1BitString("bitString");
        ParserHelper.parseStructure(bitString, inputStream);
    }
}
