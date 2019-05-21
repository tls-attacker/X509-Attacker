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
