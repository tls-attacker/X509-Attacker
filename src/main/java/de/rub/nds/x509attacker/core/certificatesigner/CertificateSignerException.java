package de.rub.nds.x509attacker.core.certificatesigner;

public class CertificateSignerException extends Exception {

    public CertificateSignerException(String message) {
        super(message);
    }

    public CertificateSignerException(Throwable cause) {
        super(cause);
    }
}
