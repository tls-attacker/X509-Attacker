/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.X509Component;
import de.rub.nds.x509attacker.x509.model.X509Explicit;

public class ExplicitPreparator<InnerField extends X509Component>
        extends X509Asn1FieldPreparator<X509Explicit<InnerField>> {

    public ExplicitPreparator(X509Chooser chooser, X509Explicit<InnerField> x509Explicit) {
        super(chooser, x509Explicit);
    }

    @Override
    protected byte[] encodeContent() {
        field.getInnerField().getPreparator(chooser).prepare();
        field.getInnerField().getHandler(chooser).adjustContextAfterPrepare();
        return ArrayConverter.concatenate(
                field.getInnerField().getTagOctets().getValue(),
                field.getInnerField().getLengthOctets().getValue(),
                field.getInnerField().getContent().getValue());
    }
}
