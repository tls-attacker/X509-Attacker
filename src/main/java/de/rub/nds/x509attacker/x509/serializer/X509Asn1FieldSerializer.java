/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.serializer;

import de.rub.nds.asn1.model.Asn1Field;
import de.rub.nds.asn1.serializer.Asn1FieldSerializer;

public class X509Asn1FieldSerializer extends Asn1FieldSerializer implements X509Serializer {

    public X509Asn1FieldSerializer(Asn1Field field) {
        super(field);
    }
}
