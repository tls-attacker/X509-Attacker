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
import de.rub.nds.x509attacker.x509.model.TbsCertificate;

public class TbsCertificateHandler extends X509FieldHandler<TbsCertificate> {

    public TbsCertificateHandler(X509Chooser chooser, TbsCertificate tbsCertificate) {
        super(chooser, tbsCertificate);
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
        if (component.getSerialNumber() != null) {
            context.setSerialNumber(component.getSerialNumber().getValue().getValue());
        }
        if (component.getSubjectUniqueId() != null
                && component.getSubjectUniqueId().getContent() != null) {
            context.setSubjectUniqueId(component.getSubjectUniqueId().getContent().getValue());
        }
        if (component.getIssuerUniqueId() != null
                && component.getIssuerUniqueId().getContent() != null) {
            context.setIssuerUniqueId(component.getIssuerUniqueId().getContent().getValue());
        }
    }
}
