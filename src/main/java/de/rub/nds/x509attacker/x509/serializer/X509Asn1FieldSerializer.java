package de.rub.nds.x509attacker.x509.serializer;

import de.rub.nds.asn1.model.Asn1Field;
import de.rub.nds.asn1.serializer.Asn1FieldSerializer;

public class X509Asn1FieldSerializer extends Asn1FieldSerializer implements X509Serializer {

    public X509Asn1FieldSerializer(Asn1Field field) {
        super(field);
    }

}
