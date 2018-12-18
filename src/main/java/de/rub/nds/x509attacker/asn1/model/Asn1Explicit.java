package de.rub.nds.x509attacker.asn1.model;

import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagClass;
import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagNumber;

import javax.xml.bind.annotation.*;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Asn1Explicit extends Asn1Field {

    @XmlElement
    private ModifiableString asn1ExplicitTagClass;

    @XmlElement
    private ModifiableInteger asn1ExplicitTagNumber;

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
    private Asn1RawField explicitField = null;

    public Asn1Explicit() {
        super();
        this.asn1ExplicitTagClass = new ModifiableString();
        this.asn1ExplicitTagNumber = new ModifiableInteger();
    }

    public ModifiableString getAsn1ExplicitTagClass() {
        return asn1ExplicitTagClass;
    }

    public void setAsn1ExplicitTagClass(ModifiableString asn1ExplicitTagClass) {
        this.asn1ExplicitTagClass = asn1ExplicitTagClass;
    }

    public ModifiableInteger getAsn1ExplicitTagNumber() {
        return asn1ExplicitTagNumber;
    }

    public void setAsn1ExplicitTagNumber(ModifiableInteger asn1ExplicitTagNumber) {
        this.asn1ExplicitTagNumber = asn1ExplicitTagNumber;
    }

    public Asn1RawField getExplicitField() {
        return explicitField;
    }

    public void setExplicitField(Asn1RawField explicitField) {
        this.explicitField = explicitField;
    }

    @Override
    protected void encodeForParentLayer() {
        byte[] content = this.createContentBytes();
        super.setAsn1TagClass(Asn1TagClass.fromString(this.asn1ExplicitTagClass.getValue()).toString());
        super.setAsn1IsConstructed(true);
        super.setAsn1TagNumber(this.asn1ExplicitTagNumber.getValue());
        super.setAsn1Content(content);
        super.encodeForParentLayer();
    }

    private byte[] createContentBytes() {
        byte[] contentBytes = null;
        if (this.explicitField != null) {
            contentBytes = this.explicitField.encode();
        }
        return contentBytes;
    }
}
