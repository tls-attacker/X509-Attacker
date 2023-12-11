/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator;

import de.rub.nds.asn1.preparator.Asn1PreparatorHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.Version;

public class VersionPreparator extends X509Asn1FieldPreparator<Version> {

    public VersionPreparator(X509Chooser chooser, Version version) {
        super(chooser, version);
    }

    @Override
    protected byte[] encodeContent() {
        Asn1PreparatorHelper.prepareField(field, chooser.getConfig().getVersion().getValue());
        return field.getContent().getOriginalValue();
    }
}
