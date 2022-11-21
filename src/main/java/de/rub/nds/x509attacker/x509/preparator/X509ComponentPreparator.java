/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509.preparator;

import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.asn1.preparator.Preparator;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class X509ComponentPreparator extends Preparator {

    private static final Logger LOGGER = LogManager.getLogger();

    protected Asn1Encodable asn1Encodable;
    protected X509CertificateConfig config;

    public X509ComponentPreparator(Asn1Encodable asn1Encodable, X509CertificateConfig config) {
        this.asn1Encodable = asn1Encodable;
    }

    @Override
    public void prepare() {
        prepareContent();
        prepareLength();
        prepareTag();
    }

    private void prepareLength() {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from
                                                                       // nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    private void prepareTag() {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from
                                                                       // nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    protected abstract void prepareContent();

    protected void prepareSubcomponent(Asn1Encodable subComponent) {
        if (subComponent == null) {
            LOGGER.warn("Not preparing null subcomponent");
        } else {
            subComponent.getPreparator().prepare();
        }
    }
}
