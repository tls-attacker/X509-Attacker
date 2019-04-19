package de.rub.nds.asn1.model;

import de.rub.nds.asn1.model.Asn1Encodable;

public abstract class Asn1Chooser extends Asn1Encodable {
    public abstract Asn1Encodable getChosenAsn1Encodable();
}
