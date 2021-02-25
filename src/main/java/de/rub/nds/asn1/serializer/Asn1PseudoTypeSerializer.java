/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.asn1.serializer;

import de.rub.nds.asn1.model.Asn1PseudoType;

public class Asn1PseudoTypeSerializer extends Asn1Serializer {

    private final Asn1PseudoType asn1PseudoType;

    public Asn1PseudoTypeSerializer(final Asn1PseudoType asn1PseudoType) {
        this.asn1PseudoType = asn1PseudoType;
    }

    @Override
    public void updateLayers() {

    }

    @Override
    public byte[] serialize() {
        return new byte[0];
    }
}
