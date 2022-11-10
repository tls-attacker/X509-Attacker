/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509.extensions;

import de.rub.nds.asn1.model.Asn1Explicit;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;
import de.rub.nds.asn1.translator.X509Translator;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1ExplicitFT;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * DistributionPointName ::= CHOICE { fullName [0] GeneralNames, nameRelativeToCRLIssuer [1] RelativeDistinguishedName }
 *
 */

public class DistributionPointName extends X509Model<Asn1Explicit> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final String type = "DistributionPointName";

    public X509Model choice;

    public static DistributionPointName getInstance(IntermediateAsn1Field intermediateAsn1Field, String identifier) {

        return new DistributionPointName(intermediateAsn1Field, identifier);

    }

    private DistributionPointName(IntermediateAsn1Field intermediateAsn1Field, String identifier) {
        asn1 = (Asn1Explicit) X509Translator.translateSingleIntermediateField(intermediateAsn1Field,
            Asn1ExplicitFT.class, identifier, type);

        // Choice
        switch (intermediateAsn1Field.getChildren().get(0).getTagNumber()) {

            case 0: // GeneralNames
                choice = ExplicitGeneralName.getInstance(intermediateAsn1Field.getChildren().get(0), "fullName");
                asn1.addChild(choice.asn1);
                break;

            case 1: // nameRelativeToCRLIssuer
                choice = ExplicitRelativeDistinguishedName.getInstance(intermediateAsn1Field.getChildren().get(0),
                    "nameRelativeToCRLIssuer");
                asn1.addChild(choice.asn1);
                break;

            default:
                LOGGER.warn(
                    "Parser Error: DistributionPointName -> Default Case triggerd; no Parser defined for Tag Number: "
                        + intermediateAsn1Field.getChildren().get(0).getTagNumber());
        }

    }

}
