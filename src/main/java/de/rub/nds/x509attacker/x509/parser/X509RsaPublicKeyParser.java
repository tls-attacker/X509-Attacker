/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser;

import de.rub.nds.asn1.parser.ParserHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.publickey.X509RsaPublicKey;
import java.io.PushbackInputStream;

public class X509RsaPublicKeyParser extends X509Asn1FieldParser<X509RsaPublicKey> {

    public X509RsaPublicKeyParser(X509Chooser chooser, X509RsaPublicKey rsaPublicKey) {
        super(chooser, rsaPublicKey);
    }

    @Override
    protected void parseContent(PushbackInputStream inputStream) {
        ParserHelper.parseAsn1Integer(encodable.getModulus(), inputStream);
        ParserHelper.parseAsn1Integer(encodable.getPublicExponent(), inputStream);
    }
}
