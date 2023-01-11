package de.rub.nds.x509attacker.x509.handler;

import de.rub.nds.asn1.oid.ObjectIdentifier;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import de.rub.nds.x509attacker.x509.base.CertificateSignatureAlgorithmIdentifier;

public class CertificateSignatureAlgorithmIdentifierHandler extends X509Handler {

    private final CertificateSignatureAlgorithmIdentifier identifier;

    public CertificateSignatureAlgorithmIdentifierHandler(X509Chooser chooser, CertificateSignatureAlgorithmIdentifier identifier) {
        super(chooser);
        this.identifier = identifier;
    }

    @Override
    public void adjustContext() {
        context.setSubjectSignatureAlgorithm(X509SignatureAlgorithm.decodeFromOidBytes(new ObjectIdentifier(identifier.getAlgorithm().getValue().getValue()).getEncoded()));
    }

}
