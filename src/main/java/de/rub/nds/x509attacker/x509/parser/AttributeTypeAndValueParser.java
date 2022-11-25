package de.rub.nds.x509attacker.x509.parser;

import de.rub.nds.asn1.model.Asn1Field;
import de.rub.nds.asn1.parser.Asn1SequenceParser;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.x509.base.AttributeTypeAndValue;
import java.io.IOException;
import java.io.InputStream;

public class AttributeTypeAndValueParser extends Asn1SequenceParser {

    private final AttributeTypeAndValue attributeTypeAndValue;

    public AttributeTypeAndValueParser(AttributeTypeAndValue attributeTypeAndValue) {
        super(attributeTypeAndValue);
        this.attributeTypeAndValue = attributeTypeAndValue;
    }

    @Override
    public void parseIndividualContentFields(InputStream inputStream) throws IOException {
        super.parseIndividualContentFields(inputStream);
        attributeTypeAndValue.setAttributeTypeConfig(X500AttributeType.decodeFromOidBytes(attributeTypeAndValue.getContent().getValue()));
        attributeTypeAndValue.setValueConfig(new String(((Asn1Field) attributeTypeAndValue.getValue()).getContent().getValue()));
    }

}
