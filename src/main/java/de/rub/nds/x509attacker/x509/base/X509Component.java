/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.x509attacker.x509.parser.X509ComponentParser;
import de.rub.nds.x509attacker.x509.preparator.X509ComponentPreparator;
import de.rub.nds.x509attacker.x509.serializer.X509ComponentSerializer;

public interface X509Component {

    public abstract X509ComponentPreparator getPreparator();

    public abstract X509ComponentParser getParser();

    public abstract X509ComponentSerializer getSerializer();
}
