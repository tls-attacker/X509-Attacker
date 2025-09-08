/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.config.extension;

import de.rub.nds.x509attacker.constants.GeneralNameChoiceType;
import de.rub.nds.x509attacker.constants.X509ExtensionType;
import de.rub.nds.x509attacker.x509.model.GeneralName;
import de.rub.nds.x509attacker.x509.model.extensions.AuthorityKeyIdentifier;

public class AuthorityKeyIdentifierConfig extends ExtensionConfig {

    private byte[] keyIdentifier;
    private GeneralNameChoiceType generalNameChoiceTypeConfig;
    private Object generalNameConfigValue;
    private int serialNumber;

    public AuthorityKeyIdentifierConfig() {
        super(X509ExtensionType.AUTHORITY_KEY_IDENTIFIER.getOid(), "authorityKeyIdentifier");
    }

    @Override
    public AuthorityKeyIdentifier getExtensionFromConfig() {
        return new AuthorityKeyIdentifier("authorityKeyIdentifier");
    }

    public byte[] getKeyIdentifier() {
        return keyIdentifier;
    }

    public void setKeyIdentifier(byte[] keyIdentifier) {
        this.keyIdentifier = keyIdentifier;
    }

    public GeneralNameChoiceType getGeneralNameChoiceTypeConfig() {
        return generalNameChoiceTypeConfig;
    }

    public void setGeneralNameChoiceTypeConfig(GeneralNameChoiceType generalNameChoiceTypeConfig) {
        this.generalNameChoiceTypeConfig = generalNameChoiceTypeConfig;
    }

    public Object getGeneralNameConfigValue() {
        return generalNameConfigValue;
    }

    public void setGeneralNameConfigValue(Object generalNameConfigValue) {
        this.generalNameConfigValue = generalNameConfigValue;
    }

    public int getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(int serialNumber) {
        this.serialNumber = serialNumber;
    }

    public GeneralName getAuthorityCertIssuer() {
        GeneralName authorityCertIssuer = new GeneralName("authorityCertIssuer");
        authorityCertIssuer.setGeneralNameChoiceTypeConfig(generalNameChoiceTypeConfig);
        authorityCertIssuer.setGeneralNameConfigValue(generalNameConfigValue);
        return authorityCertIssuer;
    }
}
