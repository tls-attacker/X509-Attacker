/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser;

import de.rub.nds.protocol.exception.ParserException;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.publickey.X509EcdhEcdsaPublicKey;
import java.io.PushbackInputStream;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class X509EcdhEcdsaPublicKeyParser extends X509Asn1FieldParser<X509EcdhEcdsaPublicKey> {

    private static final Logger LOGGER = LogManager.getLogger();

    public X509EcdhEcdsaPublicKeyParser(
            X509Chooser chooser, X509EcdhEcdsaPublicKey ecdhEcdsaPublicKey) {
        super(chooser, ecdhEcdsaPublicKey);
    }

    @Override
    protected void parseContent(PushbackInputStream inputStream) {
        try {
            // Test that input stream has correct content length
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
                } else {
                    byte[] x = inputStream.readNBytes(byteLength);
                    byte[] y = inputStream.readNBytes(byteLength);
                    encodable.setFormatByte(formatByte);
                    encodable.setxCoordinate(new BigInteger(1, x));
                    encodable.setyCoordinate(new BigInteger(1, y));
                }
            }
        } catch (Exception E) {
            throw new ParserException(E);
        }
    }
}
