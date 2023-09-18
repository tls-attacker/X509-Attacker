/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model;

import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.EdiPartyNameHandler;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.parser.EdiPartyNameParser;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.EdiPartyNamePreparator;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * EDIPartyName ::= SEQUENCE { nameAssigner [0] DirectoryString OPTIONAL, partyName [1]
 * DirectoryString } }
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class EdiPartyName extends Asn1Sequence implements X509Component {

    @HoldsModifiableVariable private X509Explicit<DirectoryString> nameAssigner;

    @HoldsModifiableVariable private X509Explicit<DirectoryString> partyName;

    private EdiPartyName() {
        super(null);
    }

    public EdiPartyName(String identifier) {
        super(identifier);
        nameAssigner =
                new X509Explicit<DirectoryString>(
                        "nameAssigner", 0, new DirectoryString("nameAssigner"));
        nameAssigner.setOptional(true);
        partyName =
                new X509Explicit<DirectoryString>("partyName", 1, new DirectoryString("partyName"));
    }

    public EdiPartyName(String identifier, int implicitTagNumber) {
        super(identifier, implicitTagNumber);
        nameAssigner =
                new X509Explicit<DirectoryString>(
                        "nameAssigner", 0, new DirectoryString("nameAssigner"));
        nameAssigner.setOptional(true);
        partyName =
                new X509Explicit<DirectoryString>("partyName", 1, new DirectoryString("partyName"));
    }

    public X509Explicit<DirectoryString> getNameAssigner() {
        return nameAssigner;
    }

    public void setNameAssigner(X509Explicit<DirectoryString> nameAssigner) {
        this.nameAssigner = nameAssigner;
    }

    public X509Explicit<DirectoryString> getPartyName() {
        return partyName;
    }

    public void setPartyName(X509Explicit<DirectoryString> partyName) {
        this.partyName = partyName;
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        return new EdiPartyNameHandler(chooser, this);
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        return new EdiPartyNameParser(chooser, this);
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        return new EdiPartyNamePreparator(chooser, this);
    }
}
