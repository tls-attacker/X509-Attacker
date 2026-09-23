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
import de.rub.nds.protocol.constants.MlDsaParameters;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * An ML-DSA public key as it appears in a certificate. RFC 9881 puts the FIPS 204 encoding of the
 * verification key (the seed rho followed by the packed vector t1) directly into the
 * subjectPublicKey BIT STRING, so there is no inner ASN.1 structure to parse.
 *
 * <p>The parameter set is not encoded in the key itself, it follows from the algorithm OID and is
 * therefore kept alongside the bytes.
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509MlDsaPublicKey implements PublicKeyContent {

    private static final Logger LOGGER = LogManager.getLogger();

    private X509PublicKeyType publicKeyType;

    private ModifiableByteArray verificationKeyBytes;

    private X509MlDsaPublicKey() {}

    public X509MlDsaPublicKey(X509PublicKeyType publicKeyType) {
        if (!publicKeyType.isMlDsa()) {
            throw new IllegalArgumentException(
                    "Not an ML-DSA public key type: " + publicKeyType.name());
        }
        this.publicKeyType = publicKeyType;
    }

    public ModifiableByteArray getVerificationKeyBytes() {
        return verificationKeyBytes;
    }

    public void setVerificationKeyBytes(ModifiableByteArray verificationKeyBytes) {
        this.verificationKeyBytes = verificationKeyBytes;
    }

    public void setVerificationKeyBytes(byte[] verificationKeyBytes) {
        this.verificationKeyBytes =
                ModifiableVariableFactory.safelySetValue(
                        this.verificationKeyBytes, verificationKeyBytes);
    }

    public MlDsaParameters getMlDsaParameters() {
        return publicKeyType.getMlDsaParameters();
    }

    @Override
    public X509PublicKeyType getX509PublicKeyType() {
        return publicKeyType;
    }

    @Override
    public void prepare(X509Chooser chooser) {
        byte[] verificationKey = chooser.getSubjectMlDsaVerificationKey();
        if (verificationKey == null) {
            throw new UnsupportedOperationException(
                    "X.509-Attacker cannot generate ML-DSA keys yet. Set"
                            + " defaultSubjectMlDsaVerificationKey in the config to prepare an"
                            + " ML-DSA certificate with a known key.");
        }
        setVerificationKeyBytes(verificationKey);
    }

    @Override
    public byte[] getEncoded(X509Chooser chooser) {
        return getVerificationKeyBytes().getValue();
    }

    @Override
    public void adjustInContext(X509Chooser chooser) {
        chooser.getContext().setSubjectPublicKeyType(publicKeyType);
        chooser.getContext().setSubjectMlDsaVerificationKey(getVerificationKeyBytes().getValue());
    }

    @Override
    public void readIn(X509Chooser chooser, byte[] bytesToRead) {
        int expectedLength = getMlDsaParameters().getPublicKeySizeBytes();
        if (bytesToRead.length != expectedLength) {
            LOGGER.warn(
                    "{} verification key has {} bytes, expected {}",
                    getMlDsaParameters().getName(),
                    bytesToRead.length,
                    expectedLength);
        }
        setVerificationKeyBytes(bytesToRead);
    }
}
