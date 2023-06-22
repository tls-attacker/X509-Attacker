/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
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
import java.io.InputStream;
import java.io.PushbackInputStream;

public class X509ChoiceParser implements X509Parser {

    private final Asn1Choice choice;
    private final X509Chooser chooser;

    public X509ChoiceParser(X509Chooser chooser, Asn1Choice choice) {
        this.choice = choice;
        this.chooser = chooser;
    }

    @Override
    public void parse(InputStream inputStream) {
        PushbackInputStream pushbackInputStream = new PushbackInputStream(inputStream);
        Asn1Header header = ParserHelper.lookAhead(pushbackInputStream);
        choice.makeSelection(
                header.getTagClass(),
                header.getTagConstructed().getBooleanValue(),
                header.getTagNumber());
        Asn1Encodable selectedChoice = choice.getSelectedChoice();
        if (selectedChoice == null) {
            throw new ParserException(
                    "Cannot make a selection for CHOICE: " + choice.getIdentifier());
        }
        if (selectedChoice instanceof X509Component) {
            X509Component x509Component = (X509Component) selectedChoice;
            x509Component.getParser(chooser).parse(pushbackInputStream);
        } else {
            ParserHelper.parseGenericField(selectedChoice, pushbackInputStream);
        }
    }
}
