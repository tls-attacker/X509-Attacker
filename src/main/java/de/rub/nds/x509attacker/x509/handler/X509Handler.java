/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.handler;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.context.X509Context;

public abstract class X509Handler {

    protected final X509Context context;
    protected final X509CertificateConfig config;
    protected final X509Chooser chooser;

    public X509Handler(X509Chooser chooser) {
        this.chooser = chooser;
        this.context = chooser.getContext();
        this.config = chooser.getConfig();
    }

    public abstract void adjustContext();
}
