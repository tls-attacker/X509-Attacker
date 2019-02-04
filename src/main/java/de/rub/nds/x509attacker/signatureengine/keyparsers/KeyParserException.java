package de.rub.nds.x509attacker.signatureengine.keyparsers;

public class KeyParserException extends Exception {

    public KeyParserException(String message) {
        super(message);
    }

    public KeyParserException(Throwable cause) {
        super(cause);
    }
}
