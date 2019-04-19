package de.rub.nds.x509.model;

import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.asn1.encoder.Asn1Encoder;
import de.rub.nds.asn1.model.Asn1FieldContainer;
import de.rub.nds.x509.encoder.X509FieldContainerEncoder;

import javax.xml.bind.annotation.*;
import java.util.LinkedList;
import java.util.List;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public abstract class X509FieldContainer<T extends Asn1FieldContainer> extends X509Field<T> {

    @XmlAnyElement(lax = true)
    @XmlElementWrapper(name = "elements")
    private List<Asn1Encodable> fields = new LinkedList<>();

    public X509FieldContainer() {
        super();
    }

    public X509FieldContainer(final T asn1Type) {
        super(asn1Type);
    }

    @Override
    public T getAsn1Field() { // Now the java compiler realizes that getAsn1Field always returns an instance of Asn1FieldContainer.
        return super.getAsn1Field();
    }

    public List<Asn1Encodable> getFields() {
        return fields;
    }

    public void setFields(List<Asn1Encodable> fields) {
        this.fields = fields;
    }

    public void addField(Asn1Encodable field) {
        this.fields.add(field);
    }

    public void addFields(List<Asn1Encodable> fields) {
        if(fields != null) {
            for(Asn1Encodable field : fields) {
                this.addField(field);
            }
        }
    }

    public void clearFields() {
        this.fields.clear();
    }

    @Override
    public Asn1Encoder getEncoder() {
        return new X509FieldContainerEncoder(this);
    }
}
