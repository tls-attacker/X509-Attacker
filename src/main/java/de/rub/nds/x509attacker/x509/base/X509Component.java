/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.asn1.parser.Asn1FieldParser;
import de.rub.nds.asn1.serializer.Asn1FieldSerializer;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.x509.preparator.X509ComponentPreparator;

public interface X509Component {

    public abstract X509ComponentPreparator getPreparator(X509CertificateConfig config);

    public abstract Asn1FieldSerializer getSerializer();

    public abstract Asn1FieldParser getParser();
}
