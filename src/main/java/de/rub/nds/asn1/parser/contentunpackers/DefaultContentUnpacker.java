package de.rub.nds.asn1.parser.contentunpackers;

public class DefaultContentUnpacker extends ContentUnpacker {

    @Override
    public byte[] unpack(final byte[] content) {
        return content;
    }
}
