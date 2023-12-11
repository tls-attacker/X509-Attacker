/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.handler;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.Version;

public class VersionHandler extends X509FieldHandler<Version> {

    public VersionHandler(X509Chooser chooser, Version version) {
        super(chooser, version);
    }

    @Override
    public void adjustContextAfterParse() {
        adjustContext();
    }

    @Override
    public void adjustContextAfterPrepare() {
        adjustContext();
    }

    public void adjustContext() {
        context.setVersion(component.getVersion());
    }
}
