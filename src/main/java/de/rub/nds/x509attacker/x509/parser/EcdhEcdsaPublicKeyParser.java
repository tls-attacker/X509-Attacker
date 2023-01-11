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
import de.rub.nds.asn1.parser.ParserException;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.publickey.EcdhEcdsaPublicKey;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;

public class EcdhEcdsaPublicKeyParser extends Asn1Parser<X509Chooser, EcdhEcdsaPublicKey> {

    public EcdhEcdsaPublicKeyParser(X509Chooser chooser, EcdhEcdsaPublicKey ecdhEcdsaPublicKey) {
        super(chooser, ecdhEcdsaPublicKey);
    }

    @Override
    public void parse(InputStream inputStream) {
        encodable.getPointOctets().getParser(chooser).parse(inputStream);
    }

    @Override
    public void parseWithoutTag(InputStream inputStream, byte[] tagOctets) {
        encodable.getPointOctets().getParser(chooser).parseWithoutTag(inputStream, tagOctets);
    }

    @Override
    public void parseIndividualContentFields(InputStream inputStream) throws IOException {
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
            // There should be two coordinates in the stream so twice the byte length
            if (inputStream.available() != byteLength * 2) {
                throw new ParserException(
                        "Not enough bytes in input stream to parse two coordinates");
            } else {
                byte[] x = inputStream.readNBytes(byteLength);
                byte[] y = inputStream.readNBytes(byteLength);
                encodable.setFormatByte(formatByte);
                encodable.setxCoordinate(new BigInteger(1, x));
                encodable.setyCoordinate(new BigInteger(1, y));
            }
        }
    }
}
