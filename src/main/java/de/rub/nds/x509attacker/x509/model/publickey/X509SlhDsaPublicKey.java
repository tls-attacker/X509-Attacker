/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model.publickey;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.protocol.constants.SlhDsaParameters;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * An SLH-DSA public key as it appears in a certificate. RFC 9909 puts the FIPS 205 encoding of the
 * public key (PK.seed followed by PK.root) directly into the subjectPublicKey BIT STRING, so there
 * is no inner ASN.1 structure to parse.
 *
 * <p>The parameter set is not encoded in the key itself, it follows from the algorithm OID and is
 * therefore kept alongside the bytes. The pure SLH-DSA and the HashSLH-DSA OIDs share the same key
 * format.
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509SlhDsaPublicKey implements PublicKeyContent {

    private static final Logger LOGGER = LogManager.getLogger();

    private X509PublicKeyType publicKeyType;

    private ModifiableByteArray publicKeyBytes;

    private X509SlhDsaPublicKey() {}

    public X509SlhDsaPublicKey(X509PublicKeyType publicKeyType) {
        if (!publicKeyType.isSlhDsa()) {
            throw new IllegalArgumentException(
                    "Not an SLH-DSA public key type: " + publicKeyType.name());
        }
        this.publicKeyType = publicKeyType;
    }

    public ModifiableByteArray getPublicKeyBytes() {
        return publicKeyBytes;
    }

    public void setPublicKeyBytes(ModifiableByteArray publicKeyBytes) {
        this.publicKeyBytes = publicKeyBytes;
    }

    public void setPublicKeyBytes(byte[] publicKeyBytes) {
        this.publicKeyBytes =
                ModifiableVariableFactory.safelySetValue(this.publicKeyBytes, publicKeyBytes);
    }

    public SlhDsaParameters getSlhDsaParameters() {
        return publicKeyType.getSlhDsaParameters();
    }

    @Override
    public X509PublicKeyType getX509PublicKeyType() {
        return publicKeyType;
    }

    @Override
    public void prepare(X509Chooser chooser) {
        byte[] publicKey = chooser.getSubjectSlhDsaPublicKey();
        if (publicKey == null) {
            throw new UnsupportedOperationException(
                    "X.509-Attacker cannot generate SLH-DSA keys yet. Set"
                            + " defaultSubjectSlhDsaPublicKey in the config to prepare an"
                            + " SLH-DSA certificate with a known key.");
        }
        setPublicKeyBytes(publicKey);
    }

    @Override
    public byte[] getEncoded(X509Chooser chooser) {
        return getPublicKeyBytes().getValue();
    }

    @Override
    public void adjustInContext(X509Chooser chooser) {
        chooser.getContext().setSubjectPublicKeyType(publicKeyType);
        chooser.getContext().setSubjectSlhDsaPublicKey(getPublicKeyBytes().getValue());
    }

    @Override
    public void readIn(X509Chooser chooser, byte[] bytesToRead) {
        int expectedLength = getSlhDsaParameters().getPublicKeySizeBytes();
        if (bytesToRead.length != expectedLength) {
            LOGGER.warn(
                    "{} public key has {} bytes, expected {}",
                    getSlhDsaParameters().getName(),
                    bytesToRead.length,
                    expectedLength);
        }
        setPublicKeyBytes(bytesToRead);
    }
}
