package de.rub.nds.x509attacker.asn1.model;

import javax.xml.bind.annotation.*;
import java.util.LinkedList;
import java.util.List;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Asn1Sequence extends Asn1Field {

    @XmlElements(value = {
            @XmlElement(name = "asn1Integer", type = Asn1Integer.class),
            @XmlElement(name = "asn1BitString", type = Asn1BitString.class),
            @XmlElement(name = "asn1OctetString", type = Asn1OctetString.class),
            @XmlElement(name = "asn1Null", type = Asn1Null.class),
            @XmlElement(name = "asn1ObjectIdentifier", type = Asn1ObjectIdentifier.class),
            @XmlElement(name = "asn1Sequence", type = Asn1Sequence.class),
            @XmlElement(name = "asn1Set", type = Asn1Set.class),
            @XmlElement(name = "asn1PrintableString", type = Asn1PrintableString.class),
            @XmlElement(name = "asn1T61String", type = Asn1T61String.class),
            @XmlElement(name = "asn1Ia5String", type = Asn1Ia5String.class),
            @XmlElement(name = "asn1UtcTime", type = Asn1UtcTime.class),
            // Todo: GeneralizedTime
            // Todo: TeletexString
            // Todo: UniversalString
            // Todo: UTF8String
            // Todo: BMPString
            // Todo: ORAddress (maybe)
            // Todo: Add X509-elements to this list

    })
    private List<Asn1RawField> sequenceFields;

    public Asn1Sequence() {
        super();
        this.sequenceFields = new LinkedList<>();
    }

    public List<Asn1RawField> getSequenceFields() {
        return sequenceFields;
    }

    public void setSequenceFields(List<Asn1RawField> sequenceFields) {
        this.sequenceFields = sequenceFields;
    }
}
