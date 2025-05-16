/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.config.extension;

import de.rub.nds.x509attacker.constants.X509ExtensionType;
import de.rub.nds.x509attacker.x509.model.extensions.KeyUsage;

public class KeyUsageConfig extends ExtensionConfig {

    private boolean digitalSignature = true;
    private boolean nonRepudiation = false;

    private boolean keyEncipherment = true;

    private boolean dataEncipherment = true;

    private boolean keyAgreement = true;

    private boolean keyCertSign = true;

    private boolean cRLSign = false;

    private boolean encipherOnly = false;

    private boolean decipherOnly = false;

    private boolean overflowInvalidation = false;
    private boolean overflowWithOne = false;

    public KeyUsageConfig() {
        super(X509ExtensionType.KEY_USAGE.getOid(), "keyUsage");
    }

    @Override
    public KeyUsage getExtensionFromConfig() {
        return new KeyUsage("keyUsage");
    }

    public boolean isDigitalSignature() {
        return digitalSignature;
    }

    public void setDigitalSignature(boolean digitalSignature) {
        this.digitalSignature = digitalSignature;
    }

    public boolean isNonRepudiation() {
        return nonRepudiation;
    }

    public void setNonRepudiation(boolean nonRepudiation) {
        this.nonRepudiation = nonRepudiation;
    }

    public boolean isKeyEncipherment() {
        return keyEncipherment;
    }

    public void setKeyEncipherment(boolean keyEncipherment) {
        this.keyEncipherment = keyEncipherment;
    }

    public boolean isDataEncipherment() {
        return dataEncipherment;
    }

    public void setDataEncipherment(boolean dataEncipherment) {
        this.dataEncipherment = dataEncipherment;
    }

    public boolean isKeyAgreement() {
        return keyAgreement;
    }

    public void setKeyAgreement(boolean keyAgreement) {
        this.keyAgreement = keyAgreement;
    }

    public boolean isKeyCertSign() {
        return keyCertSign;
    }

    public void setKeyCertSign(boolean keyCertSign) {
        this.keyCertSign = keyCertSign;
    }

    public boolean iscRLSign() {
        return cRLSign;
    }

    public void setcRLSign(boolean cRLSign) {
        this.cRLSign = cRLSign;
    }

    public boolean isEncipherOnly() {
        return encipherOnly;
    }

    public void setEncipherOnly(boolean encipherOnly) {
        this.encipherOnly = encipherOnly;
    }

    public boolean isDecipherOnly() {
        return decipherOnly;
    }

    public void setDecipherOnly(boolean decipherOnly) {
        this.decipherOnly = decipherOnly;
    }

    public boolean isOverflowInvalidation() {
        return overflowInvalidation;
    }

    public void setOverflowInvalidation(boolean overflowInvalidation) {
        this.overflowInvalidation = overflowInvalidation;
    }

    public boolean isOverflowWithOne() {
        return overflowWithOne;
    }

    public void setOverflowWithOne(boolean overflowWithOne) {
        this.overflowWithOne = overflowWithOne;
    }
}
