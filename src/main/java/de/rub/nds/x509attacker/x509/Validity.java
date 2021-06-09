/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509;

import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;
import de.rub.nds.asn1.translator.X509Translator;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1SequenceFT;

/**
 * 
 * Validity ::= SEQUENCE { notBefore Time, notAfter Time }
 * 
 */

public class Validity extends X509Model<Asn1Sequence> {

    private static final String type = "Validity";

    public Time notBefore;
    public Time notAfter;

    public static Validity getInstance(IntermediateAsn1Field intermediateAsn1Field, String identifier) {

        return new Validity(intermediateAsn1Field, identifier);

    }

    private Validity(IntermediateAsn1Field intermediateAsn1Field, String identifier) {
        asn1 = (Asn1Sequence) X509Translator.translateSingleIntermediateField(intermediateAsn1Field,
            Asn1SequenceFT.class, identifier, type);

        if (intermediateAsn1Field.getChildren().size() == 2) {
            notBefore = Time.getInstance(intermediateAsn1Field.getChildren().get(0), "notBefore");
            notAfter = Time.getInstance(intermediateAsn1Field.getChildren().get(1), "notAfter");
            asn1.addChild(notBefore.asn1);
            asn1.addChild(notAfter.asn1);
        }

    }

}
