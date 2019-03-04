package de.rub.nds.x509attacker.asn1.model;

import javax.xml.bind.annotation.*;
import java.util.LinkedList;
import java.util.List;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public abstract class Asn1FieldContainer extends Asn1Field {

    @XmlElementWrapper(name = "asn1ChildElements")
    @XmlAnyElement(lax = true)
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
