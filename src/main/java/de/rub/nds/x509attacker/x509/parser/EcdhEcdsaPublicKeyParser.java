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
import de.rub.nds.x509attacker.x509.base.publickey.EcdhEcdsaPublicKey;
import java.io.IOException;
import java.io.InputStream;

public class EcdhEcdsaPublicKeyParser extends Asn1Parser<X509Chooser, EcdhEcdsaPublicKey> {

    public EcdhEcdsaPublicKeyParser(X509Chooser chooser, EcdhEcdsaPublicKey ecdhEcdsaPublicKey) {
        super(chooser, ecdhEcdsaPublicKey);
    }

    @Override
    public void parse(InputStream inputStream) {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from
        // nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public void parseWithoutTag(InputStream inputStream, byte[] tagOctets) {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from
        // nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public void parseIndividualContentFields(InputStream inputStream) throws IOException {}
}
