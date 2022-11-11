/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.asn1.model.Asn1Boolean;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import org.bouncycastle.asn1.ASN1OctetString;

/**
 *
 * Extension ::= SEQUENCE { extnID OBJECT IDENTIFIER, critical BOOLEAN DEFAULT
 * FALSE, extnValue OCTET STRING -- contains the DER encoding of an ASN.1 value
 * -- corresponding to the extension type identified -- by extnID }
 *
 */
public class Extension extends Asn1Sequence {

    @HoldsModifiableVariable
    private Asn1ObjectIdentifier extnID;
    
    @HoldsModifiableVariable
    private Asn1Boolean critical;
    
    @HoldsModifiableVariable
    private ASN1OctetString extnValue;

    public Extension(String identifier) {
        super(identifier);
    }

    public Asn1ObjectIdentifier getExtnID() {
        return extnID;
    }

    public void setExtnID(Asn1ObjectIdentifier extnID) {
        this.extnID = extnID;
    }

    public Asn1Boolean getCritical() {
        return critical;
    }

    public void setCritical(Asn1Boolean critical) {
        this.critical = critical;
    }

    public ASN1OctetString getExtnValue() {
        return extnValue;
    }

    public void setExtnValue(ASN1OctetString extnValue) {
        this.extnValue = extnValue;
    }

}
