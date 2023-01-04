package de.rub.nds.x509attacker.x509.parser;

import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.parser.Asn1SequenceParser;

public class SubjectPublicKeyInfoParser extends Asn1SequenceParser {

    public SubjectPublicKeyInfoParser(Asn1Sequence field) {
        super(field);
    }

    
}
