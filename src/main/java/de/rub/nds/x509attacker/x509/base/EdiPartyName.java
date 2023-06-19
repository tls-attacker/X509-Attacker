/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.serializer.X509Serializer;
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

    @HoldsModifiableVariable private DirectoryString nameAssigner;

    @HoldsModifiableVariable private DirectoryString partyName;

    private EdiPartyName() {
        super(null);
    }

    public EdiPartyName(String identifier) {
        super(identifier);
        nameAssigner = new DirectoryString("nameAssigner");
        partyName = new DirectoryString("partyName");
    }

    public EdiPartyName(String identifier, int implicitTagNumber) {
        super(identifier, implicitTagNumber);
        nameAssigner = new DirectoryString("nameAssigner");
        partyName = new DirectoryString("partyName");
    }

    public DirectoryString getNameAssigner() {
        return nameAssigner;
    }

    public void setNameAssigner(DirectoryString nameAssigner) {
        this.nameAssigner = nameAssigner;
    }

    public DirectoryString getPartyName() {
        return partyName;
    }

    public void setPartyName(DirectoryString partyName) {
        this.partyName = partyName;
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        throw new UnsupportedOperationException("not implemented yet");
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        throw new UnsupportedOperationException("not implemented yet");
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        throw new UnsupportedOperationException("not implemented yet");
    }

    @Override
    public X509Serializer getSerializer(X509Chooser chooser) {
        throw new UnsupportedOperationException("not implemented yet");
    }
}
