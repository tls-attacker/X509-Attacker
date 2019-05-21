package de.rub.nds.x509attacker.linker;

public class LinkerException extends RuntimeException {

    public LinkerException(String message) {
        super(message);
    }

    public LinkerException(Throwable cause) {
        super(cause);
    }
}
