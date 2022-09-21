/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509;

import de.rub.nds.asn1.model.Asn1Explicit;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;
import de.rub.nds.asn1.translator.X509Translator;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1ExplicitFT;

/**
 *
 * Explicit Container for RelativeDistinguishedName
 *
 */
public class ExplicitRelativeDistinguishedName extends X509Model<Asn1Explicit> {

    private static final String type = "";

    public RelativeDistinguishedName relativeDistinguishedName;

    public static ExplicitRelativeDistinguishedName getInstance(IntermediateAsn1Field intermediateAsn1Field,
        String identifier) {

        return new ExplicitRelativeDistinguishedName(intermediateAsn1Field, identifier);

    }

    private ExplicitRelativeDistinguishedName(IntermediateAsn1Field intermediateAsn1Field, String identifier) {
        asn1 = (Asn1Explicit) X509Translator.translateSingleIntermediateField(intermediateAsn1Field,
            Asn1ExplicitFT.class, "explicit" + identifier, "explicit");
        if (intermediateAsn1Field.getChildren().size() == 1) {
            relativeDistinguishedName =
                RelativeDistinguishedName.getInstance(intermediateAsn1Field.getChildren().get(0), identifier);
        }
        asn1.addChild(relativeDistinguishedName.asn1);

    }

}
