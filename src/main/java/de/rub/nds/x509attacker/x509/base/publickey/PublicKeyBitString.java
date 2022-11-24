package de.rub.nds.x509attacker.x509.base.publickey;

import de.rub.nds.asn1.model.Asn1PrimitiveBitString;
import de.rub.nds.asn1.serializer.Asn1FieldSerializer;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.x509.base.X509Component;
import de.rub.nds.x509attacker.x509.preparator.publickey.PublicKeyBitStringPreparator;
import de.rub.nds.x509attacker.x509.preparator.X509ComponentPreparator;

public class PublicKeyBitString extends Asn1PrimitiveBitString implements X509Component {

    private X509Component publicKey;

    public PublicKeyBitString(String identifier, X509Component publicKey) {
        super(identifier);
        this.publicKey = publicKey;
    }

    public PublicKeyBitString(String identifier) {
        super(identifier);
    }

    public void setPublicKey(X509Component publicKey) {
        this.publicKey = publicKey;
    }

    public X509Component getPublicKey() {
        return publicKey;
    }

    @Override
    public X509ComponentPreparator getPreparator(X509CertificateConfig config) {
        return new PublicKeyBitStringPreparator(this, config);
    }

    @Override
    public Asn1FieldSerializer getSerializer() {
        return getGenericSerializer();
    }

}
