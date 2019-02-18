package de.rub.nds.x509attacker.asn1.model;

import javax.xml.bind.annotation.*;
import java.util.LinkedList;
import java.util.List;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public abstract class Asn1FieldContainer extends Asn1Field {

    @XmlElementWrapper(name = "asn1ChildElements")
    @XmlElements(value = {
            @XmlElement(name = "asn1AbstractField", type = Asn1AbstractField.class),
            @XmlElement(name = "asn1BitString", type = Asn1BitString.class),
            @XmlElement(name = "asn1BitStringValue", type = Asn1BitString.Asn1BitStringItem.class),
            @XmlElement(name = "asn1Explicit", type = Asn1Explicit.class),
            @XmlElement(name = "asn1Field", type = Asn1Field.class),
            @XmlElement(name = "asn1FieldContainer", type = Asn1FieldContainer.class),
            @XmlElement(name = "asn1Ia5String", type = Asn1Ia5String.class),
            @XmlElement(name = "asn1Ia5StringValue", type = Asn1Ia5String.Asn1Ia5StringItem.class),
            @XmlElement(name = "asn1Integer", type = Asn1Integer.class),
            @XmlElement(name = "asn1Null", type = Asn1Null.class),
            @XmlElement(name = "asn1ObjectIdentifier", type = Asn1ObjectIdentifier.class),
            @XmlElement(name = "asn1OctetString", type = Asn1OctetString.class),
            @XmlElement(name = "asn1OctetStringValue", type = Asn1OctetString.Asn1OctetStringItem.class),
            @XmlElement(name = "asn1PrintableString", type = Asn1PrintableString.class),
            @XmlElement(name = "asn1PrintableStringValue", type = Asn1PrintableString.Asn1PrintableStringItem.class),
            @XmlElement(name = "asn1RawField", type = Asn1RawField.class),
            @XmlElement(name = "asn1Sequence", type = Asn1Sequence.class),
            @XmlElement(name = "asn1Set", type = Asn1Set.class),
            @XmlElement(name = "asn1T61String", type = Asn1T61String.class),
            @XmlElement(name = "asn1T61StringValue", type = Asn1T61String.Asn1T61StringItem.class),
            @XmlElement(name = "asn1UtcTime", type = Asn1UtcTime.class),
            @XmlElement(name = "asn1UtcTimeValue", type = Asn1UtcTime.Asn1UtcTimeItem.class),
            // Todo: GeneralizedTime
            // Todo: TeletexString
            // Todo: UniversalString
            // Todo: UTF8String
            // Todo: BMPString
            // Todo: ORAddress (maybe)
    })
    private List<Asn1RawField> asn1ChildElements;

    public Asn1FieldContainer() {
        super();
        this.asn1ChildElements = new LinkedList<>();
    }

    public List<Asn1RawField> getAsn1ChildElements() {
        return asn1ChildElements;
    }

    public void setAsn1ChildElements(List<Asn1RawField> asn1ChildElements) {
        this.asn1ChildElements = asn1ChildElements;
    }

    public void addField(Asn1RawField field) {
        this.asn1ChildElements.add(field);
    }

    @Override
    protected void encodeForParentLayer() {
        byte[] content = this.createContentBytes();
        super.setAsn1Content(content);
        super.encodeForParentLayer();
    }

    private byte[] createContentBytes() {
        byte[] content;
        byte[][] containedFieldContents = new byte[this.asn1ChildElements.size()][];
        int totalSize = 0;
        int contentPos = 0;
        for (int i = 0; i < this.asn1ChildElements.size(); i++) {
            containedFieldContents[i] = this.asn1ChildElements.get(i).encode();
            totalSize += containedFieldContents[i].length;
        }
        content = new byte[totalSize];
        for (int i = 0; i < containedFieldContents.length; i++) {
            for (int j = 0; j < containedFieldContents[i].length; j++) {
                content[contentPos] = containedFieldContents[i][j];
                contentPos++;
            }
        }
        return content;
    }
}
