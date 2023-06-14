/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser;

import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackInputStream;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.publickey.X509RsaPublicKey;
import de.rub.nds.x509attacker.x509.base.publickey.X509RsaPublicKeyContentSequence;

public class X509RsaPublicKeyParser extends X509Asn1FieldParser<X509RsaPublicKey> {

    public X509RsaPublicKeyParser(X509Chooser chooser, X509RsaPublicKey rsaPublicKey) {
        super(chooser, rsaPublicKey);
    }

    @Override
    public void parse(InputStream inputStream) {
        encodable.getRsaPublicKeyContentSequence().getParser(chooser).parse(inputStream);
    }

    @Override
    public void parseWithoutTag(InputStream inputStream, byte[] tagOctets) {
        encodable
                .getRsaPublicKeyContentSequence()
                .getParser(chooser)
                .parseWithoutTag(inputStream, tagOctets);
    }

    @Override
    public void parseIndividualContentFields(InputStream inputStream) throws IOException {
        X509RsaPublicKeyContentSequence rsaContentSequence = encodable.getRsaPublicKeyContentSequence();
        rsaContentSequence.getParser(chooser).parseIndividualContentFields(inputStream);
    }

    @Override
    protected void parseContent(PushbackInputStream inputStream) {
        throw new UnsupportedOperationException("Unimplemented method 'parseContent'");
    }
}
