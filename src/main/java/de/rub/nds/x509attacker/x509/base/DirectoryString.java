/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.asn1.model.Asn1Choice;
import de.rub.nds.asn1.model.Asn1PrimitivePrintableString;
import de.rub.nds.asn1.model.Asn1PrimitiveUtf8String;
import de.rub.nds.asn1.preparator.Preparator;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * DirectoryString ::= CHOICE { teletexString TeletexString (SIZE (1..MAX)), printableString
 * PrintableString (SIZE (1..MAX)), universalString UniversalString (SIZE (1..MAX)), utf8String
 * UTF8String (SIZE (1..MAX)), bmpString BMPString (SIZE (1..MAX)) }
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class DirectoryString extends Asn1Choice implements X509Component {

    private DirectoryString() {
        super(null);
    }

    public DirectoryString(String identifier) {
        super(
                identifier,
                new Asn1Utf8String("utf8String"),
                new Asn1PrintableString("printableString"));
    }

    @Override
    public Preparator getPreparator(X509Chooser context) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Handler getHandler(X509Chooser chooser) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
