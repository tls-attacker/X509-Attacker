package de.rub.nds.x509attacker.x509.base.publickey.parameters;

import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1PrimitiveBitString;
import de.rub.nds.asn1.model.Asn1Sequence;

public class DhValidationParms extends Asn1Sequence {

    private Asn1PrimitiveBitString seed;
    private Asn1Integer pgenCounter;

    public DhValidationParms(String identifier) {
        super(identifier);
        seed = new Asn1PrimitiveBitString("seed");
        pgenCounter = new Asn1Integer("pgenCounter");
        addChild(seed);
        addChild(pgenCounter);
    }

    public Asn1PrimitiveBitString getSeed() {
        return seed;
    }

    public void setSeed(Asn1PrimitiveBitString seed) {
        this.seed = seed;
    }

    public Asn1Integer getPgenCounter() {
        return pgenCounter;
    }

    public void setPgenCounter(Asn1Integer pgenCounter) {
        this.pgenCounter = pgenCounter;
    }
}
