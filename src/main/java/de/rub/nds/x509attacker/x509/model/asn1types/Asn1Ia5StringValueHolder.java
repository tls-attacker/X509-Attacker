package de.rub.nds.x509attacker.x509.model.asn1types;

import de.rub.nds.x509attacker.asn1.model.*;

import javax.xml.bind.annotation.*;
import java.util.LinkedList;
import java.util.List;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Asn1Ia5StringValueHolder extends Asn1Ia5String {

    @XmlAttribute
    private boolean excludeFromSignature = false;

    @XmlAttribute
    private boolean excludeFromCertificate = false;

    @XmlElements(value = {
            @XmlElement(name = "asn1Integer", type = Asn1Integer.class),
            @XmlElement(name = "asn1BitString", type = Asn1BitString.class),
            @XmlElement(name = "asn1BitStringValue", type = Asn1BitString.Asn1BitStringValue.class),
            @XmlElement(name = "asn1OctetString", type = Asn1OctetString.class),
            @XmlElement(name = "asn1OctetStringValue", type = Asn1OctetString.Asn1OctetStringValue.class),
            @XmlElement(name = "asn1Null", type = Asn1Null.class),
            @XmlElement(name = "asn1ObjectIdentifier", type = Asn1ObjectIdentifier.class),
            @XmlElement(name = "asn1Sequence", type = Asn1Sequence.class),
            @XmlElement(name = "asn1Set", type = Asn1Set.class),
            @XmlElement(name = "asn1PrintableString", type = Asn1PrintableString.class),
            @XmlElement(name = "asn1PrintableStringValue", type = Asn1PrintableString.Asn1PrintableStringValue.class),
            @XmlElement(name = "asn1T61String", type = Asn1T61String.class),
            @XmlElement(name = "asn1T61StringValue", type = Asn1T61String.Asn1T61StringValue.class),
            @XmlElement(name = "asn1Ia5String", type = Asn1Ia5String.class),
            @XmlElement(name = "asn1Ia5StringValue", type = Asn1Ia5String.Asn1Ia5StringValue.class),
            @XmlElement(name = "asn1UtcTime", type = Asn1UtcTime.class),
            @XmlElement(name = "asn1UtcTimeValue", type = Asn1UtcTime.Asn1UtcTimeValue.class)
            // Todo: GeneralizedTime
            // Todo: TeletexString
            // Todo: UniversalString
            // Todo: UTF8String
            // Todo: BMPString
            // Todo: ORAddress (maybe)
            // Todo: Add X509-asn1ChildElements to this list
    })
    private List<Asn1RawField> values;

    public Asn1Ia5StringValueHolder() {
        super();
        this.values = new LinkedList<>();
    }

    public boolean isExcludeFromSignature() {
        return excludeFromSignature;
    }

    public void setExcludeFromSignature(boolean excludeFromSignature) {
        this.excludeFromSignature = excludeFromSignature;
    }

    public boolean isExcludeFromCertificate() {
        return excludeFromCertificate;
    }

    public void setExcludeFromCertificate(boolean excludeFromCertificate) {
        this.excludeFromCertificate = excludeFromCertificate;
    }

    public List<Asn1RawField> getValues() {
        return values;
    }

    public void setValues(List<Asn1RawField> values) {
        this.values = values;
    }

    @Override
    protected void encodeForParentLayer() {
        this.addFieldsToAsn1Ia5String();
        super.encodeForParentLayer();
    }

    private void addFieldsToAsn1Ia5String() {
        for (Asn1RawField field : this.values) {
            super.addField(field);
        }
    }
}
