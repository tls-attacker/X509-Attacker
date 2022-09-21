/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.TagNumber;
import de.rub.nds.asn1.model.Asn1PrimitiveGeneralizedTime;
import de.rub.nds.asn1.model.Asn1PrimitiveUtcTime;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;
import de.rub.nds.asn1.translator.X509Translator;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1PrimitiveGeneralizedTimeFT;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1PrimitiveUtcTimeFT;

/**
 *
 * Time ::= CHOICE { utcTime UTCTime, generalTime GeneralizedTime }
 *
 */

public class Time extends X509Model<Asn1Encodable> {

    private static final String type = "Time";

    public static Time getInstance(IntermediateAsn1Field intermediateAsn1Field, String identifier) {

        return new Time(intermediateAsn1Field, identifier);

    }

    private Time(IntermediateAsn1Field intermediateAsn1Field, String identifier) {
        // Choice
        if (intermediateAsn1Field.getTagNumber() == TagNumber.UTCTIME.getIntValue()) {
            asn1 = (Asn1PrimitiveUtcTime) X509Translator.translateSingleIntermediateField(intermediateAsn1Field,
                Asn1PrimitiveUtcTimeFT.class, identifier, type);
        } else if (intermediateAsn1Field.getTagNumber() == TagNumber.GENERALIZEDTIME.getIntValue()) {
            asn1 = (Asn1PrimitiveGeneralizedTime) X509Translator.translateSingleIntermediateField(intermediateAsn1Field,
                Asn1PrimitiveGeneralizedTimeFT.class, identifier, type);
        }

    }

}
