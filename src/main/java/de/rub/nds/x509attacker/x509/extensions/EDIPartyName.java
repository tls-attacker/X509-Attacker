/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.extensions;

import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.x509.base.DirectoryString;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * EDIPartyName ::= SEQUENCE { nameAssigner [0] DirectoryString OPTIONAL, partyName [1]
 * DirectoryString } }
 */
public class EDIPartyName extends Asn1Sequence {

    private static final Logger LOGGER = LogManager.getLogger();

    @HoldsModifiableVariable private DirectoryString nameAssigner;

    @HoldsModifiableVariable private DirectoryString partyName;

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
}
