package de.rub.nds.x509attacker.x509.model.extensions.subjectdirectoryattributes;

import de.rub.nds.x509attacker.x509.model.defaultvalueholders.Asn1SequenceValueHolder;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class SubjectDirectoryAttributes extends Asn1SequenceValueHolder {

    public SubjectDirectoryAttributes() {
        super();
    }
}
