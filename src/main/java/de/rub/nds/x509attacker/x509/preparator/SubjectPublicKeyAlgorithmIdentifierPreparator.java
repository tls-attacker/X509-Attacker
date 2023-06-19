package de.rub.nds.x509attacker.x509.preparator;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.SubjectPublicKeyAlgorithmIdentifier;

public class SubjectPublicKeyAlgorithmIdentifierPreparator implements X509Preparator {

    public SubjectPublicKeyAlgorithmIdentifierPreparator(X509Chooser chooser,
            SubjectPublicKeyAlgorithmIdentifier subjectPublicKeyAlgorithmIdentifier) {
    }

    @Override
    public void prepare() {
        throw new UnsupportedOperationException("Unimplemented method 'prepare'");
    }

}
