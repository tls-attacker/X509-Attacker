package de.rub.nds.asn1.encoder;

import de.rub.nds.asn1.model.Asn1Field;

public abstract class Asn1Encoder {

    public byte[] merge(byte[]... arrays) {
        byte[] result = null;
        if(arrays != null) {
            int totalLength = 0;
            int counter = 0;
            for(int i = 0; i < arrays.length; i++) {
                totalLength += arrays[i].length;
            }
            result = new byte[totalLength];
            for(int i = 0; i < arrays.length; i++) {
                System.arraycopy(arrays[i], 0, result, counter, arrays[i].length);
                counter += arrays[i].length;
            }
        }
        return result;
    }

    public abstract byte[] encode();

    public abstract Asn1Field encodeAndGetAsn1Field();
}
