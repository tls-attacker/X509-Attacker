package de.rub.nds.x509attacker.x509.parser;

import java.io.PushbackInputStream;

import de.rub.nds.asn1.constants.TagClass;
import de.rub.nds.asn1.constants.TagNumber;
import de.rub.nds.asn1.time.TimeField;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.Validity;

public class ValidityParser extends X509Asn1FieldParser<Validity> {

    public ValidityParser(X509Chooser chooser, Validity validity) {
        super(chooser, validity);
    }

    @Override
    protected void parseContent(PushbackInputStream inputStream) {
        encodable.setNotBefore((TimeField) parseTagNumberField(inputStream, TagClass.UNIVERSAL, TagNumber.GENERALIZEDTIME, TagNumber.UTCTIME));
        encodable.setNotAfter((TimeField) parseTagNumberField(inputStream, TagClass.UNIVERSAL, TagNumber.GENERALIZEDTIME, TagNumber.UTCTIME));
    }

}
