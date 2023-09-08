/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser;

import de.rub.nds.asn1.parser.Asn1Parser;
import de.rub.nds.asn1.parser.ParserHelper;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.publickey.PublicKeyBitString;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PublicKeyBitStringParser extends Asn1Parser<PublicKeyBitString> implements X509Parser {

    private static final Logger LOGGER = LogManager.getLogger();

    private final PublicKeyBitString publicKeyBitString;

    private final X509Chooser chooser;

    public PublicKeyBitStringParser(X509Chooser chooser, PublicKeyBitString publicKeyBitString) {
        super(publicKeyBitString);
        this.publicKeyBitString = publicKeyBitString;
        this.chooser = chooser;
    }

    @Override
    public void parse(BufferedInputStream inputStream) {
        ParserHelper.parseAsn1BitString(publicKeyBitString, inputStream);
        /**
         * The content of the public key bitstring itself has structure, so we need to parse it as
         * well.
         */
        publicKeyBitString.setX509PublicKeyContent(
                publicKeyBitString.createX509PublicKeyContent(chooser.getSubjectPublicKeyType()));
        LOGGER.debug(
                "PublicKey content: {}",
                ArrayConverter.bytesToHexString(publicKeyBitString.getUsedBits().getValue()));
        publicKeyBitString
                .getX509PublicKeyContent()
                .getParser(chooser)
                .parse(
                        new BufferedInputStream(
                                new ByteArrayInputStream(
                                        publicKeyBitString.getUsedBits().getValue())));

        // TODO we are adjusting the context here - check how we want to do this
        publicKeyBitString.getX509PublicKeyContent().getHandler(chooser).adjustContext();
    }
}
