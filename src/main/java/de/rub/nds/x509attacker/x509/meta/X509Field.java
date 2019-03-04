package de.rub.nds.x509attacker.x509.meta;

public interface X509Field extends Referenceable, ReferenceHolder {
    boolean isExcludeFromSignature();

    boolean isExcludeFromCertificate();
}
