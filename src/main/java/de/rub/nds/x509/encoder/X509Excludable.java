package de.rub.nds.x509.encoder;

public interface X509Excludable {
    boolean isExcludeFromSignature();

    void setExcludeFromSignature(boolean excludeFromSignature);

    boolean isExcludeFromCertificate();

    void setExcludeFromCertificate(boolean excludeFromCertificate);
}
