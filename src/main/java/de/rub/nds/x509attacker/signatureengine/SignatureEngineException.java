package de.rub.nds.x509attacker.signatureengine;

public class SignatureEngineException extends Exception {

    public SignatureEngineException(String message) {
        super(message);
    }

    public SignatureEngineException(Throwable cause) {
        super(cause);
    }
}
