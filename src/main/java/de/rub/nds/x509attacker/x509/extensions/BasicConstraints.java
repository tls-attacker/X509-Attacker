/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.extensions;

import de.rub.nds.asn1.model.Asn1Boolean;
import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint
 * INTEGER (0..MAX) OPTIONAL }
 *
 */
public class BasicConstraints extends Asn1Sequence {
    
    private static final Logger LOGGER = LogManager.getLogger();
    
    @HoldsModifiableVariable
    private Asn1Boolean ca;
    
    @HoldsModifiableVariable
    private Asn1Integer pathLenConstraint;
    
    public BasicConstraints(String identifier) {
        super(identifier);
        ca = new Asn1Boolean("ca");
        pathLenConstraint = new Asn1Integer("pathLenConstraint");
        addChild(ca);
        addChild(pathLenConstraint);
    }
    
    public Asn1Boolean getCa() {
        return ca;
    }
    
    public void setCa(Asn1Boolean ca) {
        this.ca = ca;
    }
    
    public Asn1Integer getPathLenConstraint() {
        return pathLenConstraint;
    }
    
    public void setPathLenConstraint(Asn1Integer pathLenConstraint) {
        this.pathLenConstraint = pathLenConstraint;
    }
    
}
