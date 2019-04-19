package de.rub.nds.asn1.model;

import de.rub.nds.asn1.encoder.Asn1FieldContainerEncoder;
import de.rub.nds.asn1.encoder.Asn1Encoder;

import javax.xml.bind.annotation.*;
import java.util.LinkedList;
import java.util.List;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public abstract class Asn1FieldContainer extends Asn1Field {

    @XmlAnyElement(lax = true)
    @XmlElementWrapper(name = "elements")
    private List<Asn1Encodable> children = new LinkedList<>();

    public Asn1FieldContainer() {
        super();
    }

    public Asn1FieldContainer(int tagClass, boolean isConstructed, int tagNumber) {
        super(tagClass, isConstructed, tagNumber);
    }

    public List<Asn1Encodable> getChildren() {
        return children;
    }

    public void setChildren(List<Asn1Encodable> children) {
        this.children = children;
    }

    public void addChild(Asn1Encodable child) {
        this.children.add(child);
    }

    public void addChildren(List<Asn1Encodable> children) {
        if (children != null) {
            for (Asn1Encodable child : children) {
                this.addChild(child);
            }
        }
    }

    public void clearChildren() {
        this.children.clear();
    }

    @Override
    public Asn1Encoder getEncoder() {
        return new Asn1FieldContainerEncoder(this);
    }
}
