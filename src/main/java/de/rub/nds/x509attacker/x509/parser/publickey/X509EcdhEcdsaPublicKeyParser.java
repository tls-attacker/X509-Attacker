/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser.publickey;

import de.rub.nds.protocol.exception.ParserException;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.publickey.X509EcdhEcdsaPublicKey;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import java.io.BufferedInputStream;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class X509EcdhEcdsaPublicKeyParser implements X509Parser {

    private static final Logger LOGGER = LogManager.getLogger();

    private X509Chooser chooser;

    private X509EcdhEcdsaPublicKey ecdhEcdsaPublicKey;

    public X509EcdhEcdsaPublicKeyParser(
            X509Chooser chooser, X509EcdhEcdsaPublicKey ecdhEcdsaPublicKey) {
        this.chooser = chooser;
        this.ecdhEcdsaPublicKey = ecdhEcdsaPublicKey;
    }

    public void parse(BufferedInputStream inputStream) {
        try {
            if (inputStream.available() == 0) {
                throw new ParserException("Cannot parse point format");
            }
            byte formatByte = (byte) (inputStream.read() & 0xFF);
            if (formatByte != 0x04) {
                throw new UnsupportedOperationException(
                        "Currently only supporting uncompressed points");
            } else {
                int byteLength = chooser.getSubjectNamedCurve().getByteLength();
                LOGGER.debug("Curve: " + chooser.getSubjectNamedCurve().name());
                // There should be two coordinates in the stream so twice the byte length

                if (inputStream.available() != byteLength * 2) {
                    throw new ParserException(
                            "Not exact bytes in input stream to parse two coordinates: "
                                    + inputStream.available()
                                    + " should be "
                                    + byteLength * 2);
                }
                byte[] x = inputStream.readNBytes(byteLength);
                byte[] y = inputStream.readNBytes(byteLength);
                ecdhEcdsaPublicKey.setFormatByte(formatByte);
                ecdhEcdsaPublicKey.setxCoordinate(new BigInteger(1, x));
                ecdhEcdsaPublicKey.setyCoordinate(new BigInteger(1, y));
                LOGGER.debug("Parsed public key contents successfully.");
            }
        } catch (Exception E) {
            throw new ParserException(E);
        }
    }
}
