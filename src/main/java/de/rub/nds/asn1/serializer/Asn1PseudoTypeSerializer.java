/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
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
