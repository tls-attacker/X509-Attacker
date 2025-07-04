/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser;

import de.rub.nds.asn1.model.Asn1Choice;
import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.asn1.parser.ParserHelper;
import de.rub.nds.asn1.util.Asn1Header;
import de.rub.nds.protocol.exception.ParserException;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.X509Component;
import java.io.BufferedInputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class X509ChoiceParser implements X509Parser {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Asn1Choice choice;
    private final X509Chooser chooser;

    public X509ChoiceParser(X509Chooser chooser, Asn1Choice choice) {
        this.choice = choice;
        this.chooser = chooser;
    }

    @Override
    public void parse(BufferedInputStream inputStream) {
        try {
            LOGGER.debug(
                    "Parsing choice. Looking ahead. Bytes in stream: {}", inputStream.available());
            Asn1Header header = ParserHelper.lookAhead(inputStream);
            LOGGER.debug("Found header: {}", header.toString());
            choice.makeSelection(
                    header.getTagClass(),
                    header.getTagConstructed().getBooleanValue(),
                    header.getTagNumber());
            Asn1Encodable selectedChoice = choice.getSelectedChoice();
            if (selectedChoice == null) {
                throw new ParserException(
                        "Cannot make a selection for CHOICE: " + choice.getIdentifier());
            } else {
                LOGGER.debug(
                        "Selected: {} ({})",
                        selectedChoice.getIdentifier(),
                        selectedChoice.getClass().getSimpleName());
            }
            if (selectedChoice instanceof X509Component) {
                X509Component x509Component = (X509Component) selectedChoice;
                x509Component.getParser(chooser).parse(inputStream);
                x509Component.getHandler(chooser).adjustContextAfterParse();
            } else {

                ParserHelper.parseGenericField(selectedChoice, inputStream);
            }
            LOGGER.debug("Finished parsing of X509Choice");
        } catch (Exception E) {
            throw new ParserException(
                    String.format(
                            "Exception occured in X509ChoiceParser parsing for %s",
                            choice.getIdentifier()),
                    E);
        }
    }
}
