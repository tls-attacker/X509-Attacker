/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser;

import de.rub.nds.asn1.parser.Asn1Parser;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.publickey.DhPublicKey;
import java.io.IOException;
import java.io.InputStream;

public class DhPublicKeyParser extends Asn1Parser<X509Chooser, DhPublicKey> {

    public DhPublicKeyParser(X509Chooser chooser, DhPublicKey dhPublicKey) {
        super(chooser, dhPublicKey);
    }

    @Override
    public void parse(InputStream inputStream) {
        encodable.getPublicKey().getParser(chooser).parse(inputStream);
    }

    @Override
    public void parseWithoutTag(InputStream inputStream, byte[] tagOctets) {
        encodable.getPublicKey().getParser(chooser).parseWithoutTag(inputStream, tagOctets);
    }

    @Override
    public void parseIndividualContentFields(InputStream inputStream) throws IOException {
        encodable.getPublicKey().getParser(chooser).parseIndividualContentFields(inputStream);
    }
}
