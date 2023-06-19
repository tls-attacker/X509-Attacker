package de.rub.nds.x509attacker.x509.preparator;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.CertificateSignatureAlgorithmIdentifier;

public class CertificateSignatureAlgorithmIdentifierPreparator implements X509Preparator {

    public CertificateSignatureAlgorithmIdentifierPreparator(X509Chooser chooser,
            CertificateSignatureAlgorithmIdentifier certificateSignatureAlgorithmIdentifier) {
    }

    @Override
    public void prepare() {
        throw new UnsupportedOperationException("Unimplemented method 'prepare'");
    }

}
