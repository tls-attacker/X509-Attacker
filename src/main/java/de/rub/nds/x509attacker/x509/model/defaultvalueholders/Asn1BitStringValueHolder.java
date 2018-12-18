package de.rub.nds.x509attacker.x509.model.defaultvalueholders;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.x509attacker.asn1.model.Asn1BitString;

import javax.xml.bind.annotation.*;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Asn1BitStringValueHolder extends Asn1BitString {

    @XmlAttribute
    private boolean excludeFromSignature = false;

    @XmlAttribute
    private boolean excludeFromCertificate = false;

    @XmlElement
    private ModifiableInteger cutOffBytes;

    @XmlElement
    private ModifiableByteArray bytes;

    public Asn1BitStringValueHolder() {
        super();
        this.cutOffBytes = new ModifiableInteger();
        this.bytes = new ModifiableByteArray();
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

    public ModifiableInteger getCutOffBytes() {
        return cutOffBytes;
    }

    public void setCutOffBytes(ModifiableInteger cutOffBytes) {
        this.cutOffBytes = cutOffBytes;
    }

    public ModifiableByteArray getBytes() {
        return bytes;
    }

    public void setBytes(ModifiableByteArray bytes) {
        this.bytes = bytes;
    }
}
