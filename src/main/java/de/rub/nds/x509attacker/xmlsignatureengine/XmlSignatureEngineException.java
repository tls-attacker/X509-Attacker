package de.rub.nds.x509attacker.xmlsignatureengine;

public class XmlSignatureEngineException extends RuntimeException {

    public XmlSignatureEngineException(String message) {
        super(message);
    }

    public XmlSignatureEngineException(String message, Throwable cause) {
        super(message, cause);
    }

    public XmlSignatureEngineException(Throwable cause) {
        super(cause);
    }
}
