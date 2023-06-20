/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.SubjectPublicKeyInfo;
import java.io.PushbackInputStream;

public class SubjectPublicKeyInfoParser extends X509ComponentContainerParser<SubjectPublicKeyInfo> {

    public SubjectPublicKeyInfoParser(X509Chooser chooser, SubjectPublicKeyInfo field) {
        super(chooser, field);
    }

    @Override
    protected void parseSubcomponents(PushbackInputStream inputStream) {
        encodable.getAlgorithm().getParser(chooser).parse(inputStream);
        encodable.getSubjectPublicKeyBitString().getParser(chooser).parse(inputStream);
    }
}
