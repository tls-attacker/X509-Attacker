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
import de.rub.nds.x509attacker.x509.model.extensions.SubjectAlternativeName;
import java.util.ArrayList;
import java.util.List;

public class SubjectAlternativeNameConfig extends ExtensionConfig {

    private List<GeneralNameChoiceType> generalNameChoiceTypeConfigs;
    private List<Object> generalNameConfigValues;

    public SubjectAlternativeNameConfig() {
        super(X509ExtensionType.SUBJECT_ALTERNATIVE_NAME.getOid(), "subjectAlternativeName");
    }

    @Override
    public SubjectAlternativeName getExtensionFromConfig() {
        return new SubjectAlternativeName("subjectAlternativeName");
    }

    public List<GeneralName> getSubjectAltName() {
        List<GeneralName> subjectAltName = new ArrayList<>();
        for (int i = 0; i < generalNameConfigValues.size(); i++) {
            GeneralName subjectName = new GeneralName("subjectAltName");
            subjectName.setGeneralNameChoiceTypeConfig(generalNameChoiceTypeConfigs.get(i));
            subjectName.setGeneralNameConfigValue(generalNameConfigValues.get(i));
            subjectAltName.add(subjectName);
        }

        return subjectAltName;
    }

    public List<Object> getGeneralNameConfigValues() {
        return generalNameConfigValues;
    }

    public void setGeneralNameConfigValues(List<Object> generalNameConfigValues) {
        this.generalNameConfigValues = generalNameConfigValues;
    }

    public List<GeneralNameChoiceType> getGeneralNameChoiceTypeConfigs() {
        return generalNameChoiceTypeConfigs;
    }

    public void setGeneralNameChoiceTypeConfigs(
            List<GeneralNameChoiceType> generalNameChoiceTypeConfigs) {
        this.generalNameChoiceTypeConfigs = generalNameChoiceTypeConfigs;
    }
}
