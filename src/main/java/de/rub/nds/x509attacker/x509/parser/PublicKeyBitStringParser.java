/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser;

import de.rub.nds.asn1.parser.Asn1PrimitiveBitStringParser;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.publickey.PublicKeyBitString;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

public class PublicKeyBitStringParser extends Asn1PrimitiveBitStringParser<X509Chooser> {

    private PublicKeyBitString publicKeyBitString;

    public PublicKeyBitStringParser(X509Chooser chooser, PublicKeyBitString publicKeyBitString) {
        super(chooser, publicKeyBitString);
        this.publicKeyBitString = publicKeyBitString;
    }

    @Override
    public void parseIndividualContentFields(InputStream inputStream) throws IOException {
        super.parseIndividualContentFields(inputStream);
        if (publicKeyBitString.getX509PublicKeyContent() == null) {
            publicKeyBitString.setX509PublicKeyContent(
                    publicKeyBitString.createX509PublicKeyContent(
                            chooser.getSubjectPublicKeyType()));
        }
        publicKeyBitString
                .getX509PublicKeyContent()
                .getParser(chooser)
                .parse(new ByteArrayInputStream(encodable.getValue().getValue()));
    }
}
