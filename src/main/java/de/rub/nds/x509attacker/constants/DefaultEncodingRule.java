package de.rub.nds.x509attacker.constants;

/**
 * Enumerator for encoding rules of optionals in extensions.
 */
public enum DefaultEncodingRule {
    // forces encoding
    ENCODE,
    // forces no encoding
    OMIT,
    // only encode field, if not default value as standardized
    FOLLOW_DEFAULT
}
