/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser;

import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;

import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.Name;
import de.rub.nds.x509attacker.x509.base.RelativeDistinguishedName;

public class NameParser extends X509Asn1FieldParser<Name> {

    public NameParser(X509Chooser chooser, Name name) {
        super(chooser, name);
        
    }

    @Override
    public void parseWithoutTag(InputStream inputStream, byte[] tagOctets) {
        super.parseWithoutTag(inputStream, tagOctets);
        List<RelativeDistinguishedName> rdnList = new LinkedList<>();
        for (Asn1Encodable encodable : name.getChildren()) {
            if (encodable instanceof RelativeDistinguishedName) {
                rdnList.add((RelativeDistinguishedName) encodable);
            }
        }
        name.setRelativeDistinguishedNames(rdnList);
    }

    @Override
    protected Asn1Encodable createFreshElement() {
        return new RelativeDistinguishedName("rdn");
    }

    @Override
    public void parse(InputStream inputStream) {
        parseStructure(encodable, inputStream);
        
    }
}
