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
import de.rub.nds.x509attacker.x509.model.extensions.GeneralSubtrees;
import de.rub.nds.x509attacker.x509.model.extensions.NameConstraints;

public class NameConstraintsConfig extends ExtensionConfig {

    private GeneralSubtrees permittedSubtrees;
    private GeneralSubtrees excludedSubtrees;

    public NameConstraintsConfig() {
        super(X509ExtensionType.NAME_CONSTRAINTS.getOid(), "nameConstraints");
    }

    @Override
    public NameConstraints getExtensionFromConfig() {
        return new NameConstraints("nameConstraints");
    }

    public GeneralSubtrees getPermittedSubtrees() {
        return permittedSubtrees;
    }

    public void setPermittedSubtrees(GeneralSubtrees permittedSubtrees) {
        this.permittedSubtrees = permittedSubtrees;
    }

    public GeneralSubtrees getExcludedSubtrees() {
        return excludedSubtrees;
    }

    public void setExcludedSubtrees(GeneralSubtrees excludedSubtrees) {
        this.excludedSubtrees = excludedSubtrees;
    }
}
