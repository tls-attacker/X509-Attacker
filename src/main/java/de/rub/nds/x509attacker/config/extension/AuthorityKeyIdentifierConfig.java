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
import java.util.ArrayList;
import java.util.List;

public class AuthorityKeyIdentifierConfig extends ExtensionConfig {

    private byte[] keyIdentifier;
    private List<GeneralNameChoiceType> generalNameChoiceTypeConfigs;
    private List<Object> generalNameConfigValues;
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

    public List<GeneralNameChoiceType> getGeneralNameChoiceTypeConfig() {
        return generalNameChoiceTypeConfigs;
    }

    public void setGeneralNameChoiceTypeConfig(
            List<GeneralNameChoiceType> generalNameChoiceTypeConfigs) {
        this.generalNameChoiceTypeConfigs = generalNameChoiceTypeConfigs;
    }

    public List<Object> getGeneralNameConfigValues() {
        return generalNameConfigValues;
    }

    public void setGeneralNameConfigValues(List<Object> generalNameConfigValues) {
        this.generalNameConfigValues = generalNameConfigValues;
    }

    public int getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(int serialNumber) {
        this.serialNumber = serialNumber;
    }

    public List<GeneralName> getAuthorityCertIssuers() {
        List<GeneralName> authorityCertIssuers = new ArrayList<>();
        for (int i = 0; i < generalNameConfigValues.size(); i++) {
            GeneralName authorityCertIssuer = new GeneralName("authorityCertIssuer");
            authorityCertIssuer.setGeneralNameChoiceTypeConfig(generalNameChoiceTypeConfigs.get(i));
            authorityCertIssuer.setGeneralNameConfigValue(generalNameConfigValues.get(i));
            authorityCertIssuers.add(authorityCertIssuer);
        }

        return authorityCertIssuers;
    }
}
