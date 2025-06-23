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
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.context.X509Context;
import de.rub.nds.x509attacker.x509.model.X509Component;

public abstract class X509FieldHandler<ComponentT extends X509Component> implements X509Handler {

    protected final X509Chooser chooser;
    protected final ComponentT component;
    protected final X509Context context;
    protected final X509CertificateConfig config;

    public X509FieldHandler(X509Chooser chooser, ComponentT component) {
        this.chooser = chooser;
        this.component = component;
        this.context = chooser.getContext();
        this.config = chooser.getConfig();
    }
}
