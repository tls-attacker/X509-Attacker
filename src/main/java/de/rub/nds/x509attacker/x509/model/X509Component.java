/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model;

import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1Field;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.serializer.X509Asn1FieldSerializer;
import de.rub.nds.x509attacker.x509.serializer.X509Serializer;

public interface X509Component extends Asn1Encodable {
    public X509Handler getHandler(X509Chooser chooser);

    public X509Parser getParser(X509Chooser chooser);

    public default X509Serializer getSerializer(X509Chooser chooser) {
        if (this instanceof Asn1Field) {
            return new X509Asn1FieldSerializer((Asn1Field) this);
        } else {
            throw new RuntimeException("Component did not overwrite getSerializer()");
        }
    }

    public X509Preparator getPreparator(X509Chooser chooser);
}
