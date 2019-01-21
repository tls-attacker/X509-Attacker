package de.rub.nds.x509attacker.x509.model.types.certificatepolicies;

import de.rub.nds.x509attacker.x509.model.asn1types.Asn1SequenceValueHolder;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class UserNotice extends Asn1SequenceValueHolder {

    public UserNotice() {
        super();
    }
}
