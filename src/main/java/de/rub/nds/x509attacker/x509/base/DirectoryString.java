/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.asn1.model.Asn1Choice;
import de.rub.nds.asn1.model.Asn1PrimitivePrintableString;
import de.rub.nds.asn1.model.Asn1PrimitiveUtf8String;
import de.rub.nds.asn1.parser.Asn1FieldParser;
import de.rub.nds.asn1.preparator.Preparator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * DirectoryString ::= CHOICE { teletexString TeletexString (SIZE (1..MAX)), printableString PrintableString (SIZE
 * (1..MAX)), universalString UniversalString (SIZE (1..MAX)), utf8String UTF8String (SIZE (1..MAX)), bmpString
 * BMPString (SIZE (1..MAX)) }
 *
 */
public class DirectoryString extends Asn1Choice {

    private static final Logger LOGGER = LogManager.getLogger();

    public DirectoryString(String identifier) {
        super(identifier, new Asn1PrimitiveUtf8String("utf8String"),
            new Asn1PrimitivePrintableString("printableString"));
    }

    @Override
    public Preparator getGenericPreparator() {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from
        // nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

}
