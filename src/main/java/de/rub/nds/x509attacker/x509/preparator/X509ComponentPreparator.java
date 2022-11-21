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
import de.rub.nds.asn1.model.Asn1Field;
import de.rub.nds.asn1.preparator.Asn1FieldPreparator;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.x509.base.X509Component;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class X509ComponentPreparator<T extends Asn1Field> extends Asn1FieldPreparator<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected final T instance;
    protected final X509CertificateConfig config;

    public X509ComponentPreparator(T t, X509CertificateConfig config) {
        super(t);
        this.instance = t;
        this.config = config;
    }

    protected void prepareSubcomponent(X509Component subComponent, X509CertificateConfig config) {
        if (subComponent == null) {
            LOGGER.warn("Not preparing null subcomponent");
        } else {
            subComponent.getPreparator(config).prepare();
        }
    }

    protected void prepareSubcomponent(Asn1Encodable subComponent) {
        if (subComponent == null) {
            LOGGER.warn("Not preparing null subcomponent");
        } else {
            subComponent.getGenericPreparator().prepare();
        }
    }

}
