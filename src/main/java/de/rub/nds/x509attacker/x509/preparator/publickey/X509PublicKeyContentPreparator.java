/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator.publickey;

import de.rub.nds.asn1.preparator.Preparator;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.publickey.X509PublicKeyContent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class X509PublicKeyContentPreparator<Field extends X509PublicKeyContent>
        extends Preparator {

    private static final Logger LOGGER = LogManager.getLogger();

    protected final Field field;
    protected final X509Chooser chooser;

    public X509PublicKeyContentPreparator(X509Chooser chooser, final Field field) {
        this.field = field;
        this.chooser = chooser;
    }
}
