/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1Explicit;
import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;
import de.rub.nds.asn1.translator.X509Translator;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1ExplicitFT;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1IntegerFT;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1SequenceFT;
import java.util.LinkedList;
import java.util.List;

/**
 * 
 * Version ::= INTEGER {v1(0), v2(1), v3(2) }
 * 
 */
public class Version extends X509Model<Asn1Explicit> {

    private static final String type = "Version";

    public Asn1Integer version;

    public static Version getInstance(IntermediateAsn1Field intermediateAsn1Field, String identifier) {

        return new Version(intermediateAsn1Field, identifier);
    }

    private Version(IntermediateAsn1Field intermediateAsn1Field, String identifier) {

        asn1 = (Asn1Explicit) X509Translator.translateSingleIntermediateField(intermediateAsn1Field,
            Asn1ExplicitFT.class, "explicit" + identifier, "ExplicitContainer");

        version =
            (Asn1Integer) X509Translator.translateSingleIntermediateField(intermediateAsn1Field.getChildren().get(0),
                Asn1IntegerFT.class, identifier, type);

        asn1.addChild(version);

    }

}
