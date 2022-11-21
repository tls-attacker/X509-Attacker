package de.rub.nds.x509attacker.x509.base.publickey.parameters;

import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1Sequence;

public class DssParameters extends Asn1Sequence {

    private Asn1Integer p;
    private Asn1Integer q;
    private Asn1Integer g;

    public DssParameters(String identifier) {
        super(identifier);
        this.p = new Asn1Integer("p");
        this.q = new Asn1Integer("q");
        this.g = new Asn1Integer("g");
        addChild(p);
        addChild(q);
        addChild(g);
    }

    public Asn1Integer getP() {
        return p;
    }

    public void setP(Asn1Integer p) {
        this.p = p;
    }

    public Asn1Integer getQ() {
        return q;
    }

    public void setQ(Asn1Integer q) {
        this.q = q;
    }

    public Asn1Integer getG() {
        return g;
    }

    public void setG(Asn1Integer g) {
        this.g = g;
    }

}
