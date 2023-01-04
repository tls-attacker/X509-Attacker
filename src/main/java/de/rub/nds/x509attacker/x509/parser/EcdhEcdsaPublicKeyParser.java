/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser;

import de.rub.nds.asn1.parser.Asn1FieldParser;
import de.rub.nds.x509attacker.x509.base.publickey.EcdhEcdsaPublicKey;
import java.io.IOException;
import java.io.InputStream;

public class EcdhEcdsaPublicKeyParser extends Asn1FieldParser<EcdhEcdsaPublicKey> {

    public EcdhEcdsaPublicKeyParser(EcdhEcdsaPublicKey ecdhEcdsaPublicKey) {
        super(ecdhEcdsaPublicKey);
    }

    @Override
    public void parseIndividualContentFields(InputStream inputStream) throws IOException {
        encodable.setValue(inputStream.readAllBytes()); // TODO fix unused bits
        encodable.setUnusedBits((byte) 0); // TODO not correct
        // TODO Decode PublicKey
    }
}
