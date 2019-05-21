package de.rub.nds.asn1.model;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.serializer.Asn1PseudoTypeSerializer;
import de.rub.nds.asn1.serializer.Asn1Serializer;

import javax.xml.bind.annotation.*;
import javax.xml.namespace.QName;
import java.util.HashMap;
import java.util.Map;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public abstract class Asn1PseudoType implements Asn1Encodable {

    @XmlAttribute(name = "identifier")
    private String identifier = "";

    @XmlAttribute(name = "type")
    private String type = "";

    @XmlAnyAttribute
    private Map<QName, String> attributes = new HashMap<>();

    public Asn1PseudoType() {

    }

    @Override
    public String getIdentifier() {
        return identifier;
    }

    @Override
    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }

    @Override
    public String getType() {
        return type;
    }

    @Override
    public void setType(String type) {
        this.type = type;
    }

    public boolean hasAttribute(final String attributeName) {
        return this.attributes.containsKey(new QName(attributeName));
    }

    public String getAttribute(final String attributeName) {
        String attribute = null;
        QName attributeQName = new QName(attributeName);
        if (this.attributes.containsKey(attributeQName)) {
            attribute = this.attributes.get(attributeQName);
        }
        return attribute;
    }

    public void setAttribute(final String attributeName, final String attributeValue) {
        this.attributes.put(new QName(attributeName), attributeValue);
    }

    public Asn1Serializer getSerializer() {
        return new Asn1PseudoTypeSerializer(this);
    }
}
