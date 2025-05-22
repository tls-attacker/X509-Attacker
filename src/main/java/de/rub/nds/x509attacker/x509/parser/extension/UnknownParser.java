/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser.extension;

import de.rub.nds.protocol.exception.ParserException;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.extensions.Unknown;
import java.io.BufferedInputStream;
import java.io.IOException;

/**
 * Parser for {@link Unknown} extension. Used for all extensions where OID cannot be determined or
 * is not implemented.
 */
public class UnknownParser extends ExtensionParser<Unknown> {

    public UnknownParser(X509Chooser chooser, Unknown extension) {
        super(chooser, extension);
    }

    @Override
    void parseExtensionContent(BufferedInputStream inputStream) {
        try {
            field.setContent(inputStream.readAllBytes());
        } catch (IOException E) {
            throw new ParserException("Could not read all bytes of unknown extension.");
        }
    }
}
