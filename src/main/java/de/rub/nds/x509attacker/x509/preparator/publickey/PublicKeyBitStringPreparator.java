package de.rub.nds.x509attacker.x509.preparator.publickey;

import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.x509.base.publickey.PublicKeyBitString;
import de.rub.nds.x509attacker.x509.preparator.X509ComponentPreparator;

public class PublicKeyBitStringPreparator extends X509ComponentPreparator<PublicKeyBitString> {

    public PublicKeyBitStringPreparator(PublicKeyBitString publicKeyBitString, X509CertificateConfig config) {
        super(publicKeyBitString, config);
    }

    @Override
    protected byte[] encodeContent() {
        field.getPublicKey().getPreparator(config).prepare();
        instance.setUnusedBits((byte) 0);
        instance.setValue(instance.getPublicKey().getSerializer().serialize());
        return instance.getValue().getValue();
    }

}
