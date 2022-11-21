package de.rub.nds.x509attacker.x509.base.publickeys;

import de.rub.nds.asn1.model.Asn1Integer;

public class DsaPublicKey extends Asn1Integer implements SubjectPublicKey {

    public DsaPublicKey() {
        super("dsaPublicKey");

    }

}
