package de.rub.nds.x509attacker.core.certificatelinker;

public class CertificateLinkerException extends Exception {

    public CertificateLinkerException(String message) {
        super(message);
    }

    public CertificateLinkerException(Throwable cause) {
        super(cause);
    }
}
