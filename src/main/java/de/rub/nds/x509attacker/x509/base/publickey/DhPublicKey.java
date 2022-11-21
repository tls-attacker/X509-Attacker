package de.rub.nds.x509attacker.x509.base.publickeys;

import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.preparator.Preparator;

public class DhPublicKey extends Asn1Integer implements SubjectPublicKey {

    public DhPublicKey() {
        super("dhPublicKey");
    }

    @Override
    public Preparator getPreparator() {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
