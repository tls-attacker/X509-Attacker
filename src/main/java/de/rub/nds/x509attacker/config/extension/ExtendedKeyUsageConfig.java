/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.config.extension;

import de.rub.nds.x509attacker.constants.ExtendedKeyUsageType;
import de.rub.nds.x509attacker.constants.X509ExtensionType;
import de.rub.nds.x509attacker.x509.model.extensions.ExtendedKeyUsage;
import java.util.ArrayList;
import java.util.List;

public class ExtendedKeyUsageConfig extends ExtensionConfig {

    private List<ExtendedKeyUsageType> extendedKeyUsages =
            new ArrayList<>(List.of(ExtendedKeyUsageType.SERVER_AUTH));

    public ExtendedKeyUsageConfig() {
        super(X509ExtensionType.EXTENDED_KEY_USAGE.getOid(), "extendedKeyUsage");
    }

    @Override
    public ExtendedKeyUsage getExtensionFromConfig() {
        return new ExtendedKeyUsage("extendedKeyUsage");
    }

    public List<ExtendedKeyUsageType> getExtendedKeyUsages() {
        return extendedKeyUsages;
    }

    public void setExtendedKeyUsages(List<ExtendedKeyUsageType> extendedKeyUsages) {
        this.extendedKeyUsages = extendedKeyUsages;
    }
}
