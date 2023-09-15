/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser.publickey;

import de.rub.nds.protocol.constants.PointFormat;
import de.rub.nds.protocol.crypto.ec.Point;
import de.rub.nds.protocol.crypto.ec.PointFormatter;
import de.rub.nds.protocol.exception.ParserException;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.publickey.X509EcdhEcdsaPublicKey;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import java.io.BufferedInputStream;
import java.io.IOException;
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
        LOGGER.debug("Parsing X509EcdhEcdsaPublicKey");
        try {
            if (inputStream.available() == 0) {
                throw new ParserException("Cannot parse point format");
            }
            byte[] encodedPointBytes = readEncodedPointBytes(inputStream);
            Point point = decodePoint(encodedPointBytes);
            byte formatByte = (byte) encodedPointBytes[0];
            LOGGER.debug("Curve: {}", chooser.getSubjectNamedCurve().name());
            PointFormat format = PointFormat.fromAnsiX509FormatIdentifier(formatByte);
            LOGGER.debug(
                    "Parsed Format: {} ({})",
                    formatByte,
                    format == null ? "unknown" : format.name());

            ecdhEcdsaPublicKey.setFormatByte(formatByte);
            ecdhEcdsaPublicKey.setxCoordinate(point.getFieldX().getData());
            ecdhEcdsaPublicKey.setyCoordinate(point.getFieldY().getData());
            LOGGER.debug("Parsed X: {}", ecdhEcdsaPublicKey.getxCoordinate().getValue());
            LOGGER.debug("Parsed Y: {}", ecdhEcdsaPublicKey.getyCoordinate().getValue());
        } catch (Exception E) {
            throw new ParserException(E);
        }
    }

    private byte[] readEncodedPointBytes(BufferedInputStream inputStream) throws IOException {
        return inputStream.readAllBytes();
    }

    private Point decodePoint(byte[] encodedPointBytes) {
        return PointFormatter.formatFromByteArray(
                chooser.getSubjectNamedCurve().getParameters(), encodedPointBytes);
    }
}
