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
import de.rub.nds.x509attacker.x509.model.extensions.IssuerAlternativeName;
import java.util.ArrayList;
import java.util.List;

public class IssuerAlternativeNameConfig extends ExtensionConfig {

    private List<GeneralNameChoiceType> generalNameChoiceTypeConfigs;
    private List<Object> generalNameConfigValues;

    public IssuerAlternativeNameConfig() {
        super(X509ExtensionType.ISSUER_ALTERNATIVE_NAME.getOid(), "issuerAltName");
    }

    @Override
    public IssuerAlternativeName getExtensionFromConfig() {
        return new IssuerAlternativeName("issuerAltName");
    }

    public List<GeneralName> getIssuerAltName() {
        List<GeneralName> issuerAltName = new ArrayList<>();
        for (int i = 0; i < generalNameConfigValues.size(); i++) {
            GeneralName issuerName = new GeneralName("issuerAltName");
            issuerName.setGeneralNameChoiceTypeConfig(generalNameChoiceTypeConfigs.get(i));
            issuerName.setGeneralNameConfigValue(generalNameConfigValues.get(i));
            issuerAltName.add(issuerName);
        }
        return issuerAltName;
    }

    public List<GeneralNameChoiceType> getGeneralNameChoiceTypeConfigs() {
        return generalNameChoiceTypeConfigs;
    }

    public void setGeneralNameChoiceTypeConfigs(
            List<GeneralNameChoiceType> generalNameChoiceTypeConfigs) {
        this.generalNameChoiceTypeConfigs = generalNameChoiceTypeConfigs;
    }

    public List<Object> getGeneralNameConfigValues() {
        return generalNameConfigValues;
    }

    public void setGeneralNameConfigValues(List<Object> generalNameConfigValues) {
        this.generalNameConfigValues = generalNameConfigValues;
    }
}
