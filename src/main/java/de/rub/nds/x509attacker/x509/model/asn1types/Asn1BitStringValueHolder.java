package de.rub.nds.x509attacker.x509.model.asn1types;

import de.rub.nds.x509attacker.asn1.model.*;
import de.rub.nds.x509attacker.x509.model.types.basiccertificate.*;

import javax.xml.bind.annotation.*;
import java.util.LinkedList;
import java.util.List;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Asn1BitStringValueHolder extends Asn1BitString {

    @XmlAttribute
    private boolean excludeFromSignature = false;

    @XmlAttribute
    private boolean excludeFromCertificate = false;

    @XmlElements(value = {
            // Todo: More ASN.1 fields once they are implemented
            @XmlElement(name = "asn1AbstractField", type = Asn1AbstractField.class),
            @XmlElement(name = "asn1BitString", type = Asn1BitString.class),
            @XmlElement(name = "asn1BitStringValue", type = Asn1BitStringItem.class),
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

            @XmlElement(name = "asn1BitStringValueHolder", type = Asn1BitStringValueHolder.class),
            @XmlElement(name = "asn1Ia5StringValueHolder", type = Asn1Ia5StringValueHolder.class),
            @XmlElement(name = "asn1IntegerValueHolder", type = Asn1IntegerValueHolder.class),
            @XmlElement(name = "asn1NullValueHolder", type = Asn1NullValueHolder.class),
            @XmlElement(name = "asn1ObjectIdentifierValueHolder", type = Asn1ObjectIdentifierValueHolder.class),
            @XmlElement(name = "asn1OctetStringValueHolder", type = Asn1ObjectIdentifierValueHolder.class),
            @XmlElement(name = "asn1PrintableStringValueHolder", type = Asn1PrintableStringValueHolder.class),
            @XmlElement(name = "asn1SequenceValueHolder", type = Asn1SequenceValueHolder.class),
            @XmlElement(name = "asn1SetValueHolder", type = Asn1SetValueHolder.class),
            @XmlElement(name = "asn1T61StringValueHolder", type = Asn1T61StringValueHolder.class),
            @XmlElement(name = "asn1UtcTimeValueHolder", type = Asn1UtcTimeValueHolder.class),

            // Todo: More X.509 fields

            @XmlElement(name = "algorithmIdentifier", type = AlgorithmIdentifier.class),
            @XmlElement(name = "attributeType", type = AttributeType.class),
            @XmlElement(name = "attributeTypeAndValue", type = AttributeTypeAndValue.class),
            @XmlElement(name = "certificateSerialNumber", type = CertificateSerialNumber.class),
            @XmlElement(name = "extension", type = Extension.class),
            @XmlElement(name = "extensions", type = Extensions.class),
            @XmlElement(name = "rdnSequence", type = RdnSequence.class),
            @XmlElement(name = "relativeDistinguishedName", type = RelativeDistinguishedName.class),
            @XmlElement(name = "subjectPublicKeyInfo", type = SubjectPublicKeyInfo.class),
            @XmlElement(name = "tbsCertificate", type = TbsCertificate.class),
            @XmlElement(name = "uniqueIdentifier", type = UniqueIdentifier.class),
            @XmlElement(name = "validity", type = Validity.class),
            @XmlElement(name = "version", type = Version.class),

            // Todo: More X.509 fields
    })
    private List<Asn1RawField> values;

    public Asn1BitStringValueHolder() {
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
        this.addFieldsToAsn1BitString();
        super.encodeForParentLayer();
    }

    private void addFieldsToAsn1BitString() {
        for (Asn1RawField field : this.values) {
            super.addField(field);
        }
    }
}
