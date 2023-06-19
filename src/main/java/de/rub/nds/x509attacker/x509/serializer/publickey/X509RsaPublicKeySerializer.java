package de.rub.nds.x509attacker.x509.serializer.publickey;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.publickey.X509RsaPublicKey;
import de.rub.nds.x509attacker.x509.serializer.X509Serializer;

public class X509RsaPublicKeySerializer implements X509Serializer {

    public X509RsaPublicKeySerializer(X509Chooser chooser, X509RsaPublicKey x509RsaPublicKey) {
    }

    @Override
    public byte[] serialize() {
        throw new UnsupportedOperationException("Unimplemented method 'serialize'");
    }
}
