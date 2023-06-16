package de.rub.nds.x509attacker.x509.parser;

import java.io.PushbackInputStream;

import de.rub.nds.asn1.constants.TagClass;
import de.rub.nds.asn1.constants.UniversalTagNumber;
import de.rub.nds.asn1.time.TimeField;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.Validity;

public class ValidityParser extends X509Asn1FieldParser<Validity> {

    public ValidityParser(X509Chooser chooser, Validity validity) {
        super(chooser, validity);
    }

    @Override
    protected void parseContent(PushbackInputStream inputStream) {
        encodable.setNotBefore((TimeField) ParserHelper.parseTagNumberField(inputStream, TagClass.UNIVERSAL,
                UniversalTagNumber.GENERALIZEDTIME, UniversalTagNumber.UTCTIME));
        encodable.setNotAfter((TimeField) ParserHelper.parseTagNumberField(inputStream, TagClass.UNIVERSAL,
                UniversalTagNumber.GENERALIZEDTIME, UniversalTagNumber.UTCTIME));
    }

}
