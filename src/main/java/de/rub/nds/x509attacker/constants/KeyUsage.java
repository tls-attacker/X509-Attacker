package de.rub.nds.x509attacker.constants;

public enum KeyUsage {
    DIGITAL_SIGNATURE(128),
    NON_REPUDIATION(64),
    KEY_ENCIPHERMENT(32),
    DATA_ENCIPHERMENT(16),
    KEY_AGREEMENT(8),
    KEY_CERT_SIGN(4),
    CRL_SIGN(2),
    ENCIPHERMENT_ONLY(1),
    DECIPHERMENT_ONLY(32768);

    private int value;

    private KeyUsage(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }
}
