
package de.rub.nds.x509attacker.exceptions;

/**
 * Exception thrown if a modification of a X509Certificate failed.
 * 
 */
public class X509ModificationException extends Exception {

    public X509ModificationException() {
    }

    public X509ModificationException(String message) {
        super(message);
    }

    public X509ModificationException(String message, Throwable cause) {
        super(message, cause);
    }

    public X509ModificationException(Throwable cause) {
        super(cause);
    }

    public X509ModificationException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }   
}
