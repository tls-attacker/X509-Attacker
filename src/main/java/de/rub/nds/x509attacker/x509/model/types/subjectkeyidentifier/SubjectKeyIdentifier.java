package de.rub.nds.x509attacker.x509.model.types.subjectkeyidentifier;

import de.rub.nds.x509attacker.x509.model.types.authoritykeyidentifier.KeyIdentifier;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class SubjectKeyIdentifier extends KeyIdentifier {

    public SubjectKeyIdentifier() {
        super();
    }
}
