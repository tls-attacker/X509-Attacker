package de.rub.nds.signatureengine.keyparsers;

public class KeyParserException extends Exception {

    public KeyParserException(String message) {
        super(message);
    }

    public KeyParserException(Throwable cause) {
        super(cause);
    }
}
