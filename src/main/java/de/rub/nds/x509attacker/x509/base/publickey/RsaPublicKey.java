package de.rub.nds.x509attacker.x509.base.publickeys;

import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.preparator.Preparator;

public class RsaPublicKey extends Asn1Sequence implements SubjectPublicKey {

    private Asn1Integer modulus;
    private Asn1Integer publicExponent;

    public RsaPublicKey() {
        super("rsaPublicKey");
        modulus = new Asn1Integer("modulus");
        publicExponent = new Asn1Integer("publicExponent");
        addChild(modulus);
        addChild(publicExponent);
    }

    public Asn1Integer getModulus() {
        return modulus;
    }

    public void setModulus(Asn1Integer modulus) {
        this.modulus = modulus;
    }

    public Asn1Integer getPublicExponent() {
        return publicExponent;
    }

    public void setPublicExponent(Asn1Integer publicExponent) {
        this.publicExponent = publicExponent;
    }

    @Override
    public Preparator getPreparator() {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }
}
