/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.extensions;

import de.rub.nds.asn1.handler.Handler;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.DirectoryString;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * EDIPartyName ::= SEQUENCE { nameAssigner [0] DirectoryString OPTIONAL, partyName [1]
 * DirectoryString } }
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class EDIPartyName extends Asn1Sequence<X509Chooser> {

    private static final Logger LOGGER = LogManager.getLogger();

    @HoldsModifiableVariable private DirectoryString nameAssigner;

    @HoldsModifiableVariable private DirectoryString partyName;

    private EDIPartyName() {
        super(null);
    }

    public EDIPartyName(String identifier) {
        super(identifier);
        nameAssigner = new DirectoryString("nameAssigner");
        partyName = new DirectoryString("partyName");
        addChild(nameAssigner);
        addChild(partyName);
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
    public Handler getHandler(X509Chooser chooser) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
