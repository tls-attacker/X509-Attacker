package de.rub.nds.asn1.translators;

public class TranslatorException extends Exception {

    public TranslatorException(Throwable e) {
        super(e);
    }

    public TranslatorException(String message) {
        super(message);
    }
}
