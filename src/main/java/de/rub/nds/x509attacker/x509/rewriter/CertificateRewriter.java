/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.rewriter;

import de.rub.nds.asn1.model.Asn1Container;
import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1Field;
import de.rub.nds.modifiablevariable.util.Modifiable;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificateRewriter {

    private static final Logger LOGGER = LogManager.getLogger();

    public CertificateRewriter() {}

    public void fixateNonContainerContent(Asn1Container container) {
        for (Asn1Encodable encodable : container.getChildren()) {
            if (encodable instanceof Asn1Container) {
                fixateNonContainerContent((Asn1Container) encodable);
            } else if (encodable instanceof Asn1Field) {
                fixateAsn1Field(encodable);
            } else {
                LOGGER.info("Not sure what to do here: " + encodable.getClass().getSimpleName());
            }
        }
    }

    private void fixateAsn1Field(Asn1Encodable encodable) {
        if (((Asn1Field) encodable).getContent() != null
                && ((Asn1Field) encodable).getContent().getValue() != null) {
            ((Asn1Field) encodable)
                    .setContent(
                            Modifiable.explicit(((Asn1Field) encodable).getContent().getValue()));
        } else if ((((Asn1Field) encodable).getContent() == null
                        || ((Asn1Field) encodable).getContent().getValue() == null)
                && encodable.isOptional()) {
            Asn1Field field = (Asn1Field) encodable;
            field.setContent(Modifiable.explicit(new byte[0]));
            field.setTagOctets(Modifiable.explicit(new byte[0]));
            field.setLengthOctets(Modifiable.explicit(new byte[0]));
        }
    }
}
