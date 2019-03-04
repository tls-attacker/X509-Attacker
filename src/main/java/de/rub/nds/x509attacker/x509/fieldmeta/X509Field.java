package de.rub.nds.x509attacker.x509.fieldmeta;

public interface X509Field extends Referenceable, ReferenceHolder {
    byte[] encodeForCertificate();

    byte[] encodeForSignature();
}
