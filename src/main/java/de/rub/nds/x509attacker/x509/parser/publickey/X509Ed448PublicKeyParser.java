/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser.publickey;

import de.rub.nds.asn1.parser.ParserHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.publickey.X509Ed448PublicKey;
import de.rub.nds.x509attacker.x509.parser.X509ComponentParser;
import java.io.BufferedInputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class X509Ed448PublicKeyParser extends X509ComponentParser<X509Ed448PublicKey> {

    private static final Logger LOGGER = LogManager.getLogger();

    public X509Ed448PublicKeyParser(X509Chooser chooser, X509Ed448PublicKey ed448PublicKey) {
        super(chooser, ed448PublicKey);
    }

    @Override
    public void parse(BufferedInputStream inputStream) {
        LOGGER.debug("Parsing X509Ed448PublicKey");
        ParserHelper.parseAsn1OctetString(encodable, inputStream);
        LOGGER.debug("Parsed Ed448 public key");
    }
}
