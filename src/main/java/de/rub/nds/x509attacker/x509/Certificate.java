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
import de.rub.nds.asn1.model.Asn1Container;
import de.rub.nds.asn1.model.Asn1Field;
import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1PrimitiveBitString;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;
import de.rub.nds.asn1.translator.Asn1Translator;
import de.rub.nds.asn1.translator.ContextComponent;
import de.rub.nds.asn1.translator.ContextComponentOption;
import de.rub.nds.asn1.translator.X509Translator;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1IntegerFT;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1PrimitiveBitStringFT;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1SequenceFT;
import de.rub.nds.asn1.translator.fieldtranslators.FieldTranslator;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.List;
import java.util.Map;

/**
 *
 * Certificate ::= SEQUENCE { tbsCertificate TBSCertificate, signatureAlgorithm AlgorithmIdentifier, signature BIT
 * STRING }
 * 
 */
public class Certificate extends X509Model<Asn1Sequence> {

    private static final String type = "Certificate";

    public TBSCertificate tbsCertificate;
    public AlgorithmIdentifier signatureAlgorithm;
    public Asn1PrimitiveBitString signatureValue;

    public static Certificate getInstance(IntermediateAsn1Field intermediateAsn1Field, String identifier) {

        return new Certificate(intermediateAsn1Field, identifier);

    }

    private Certificate(IntermediateAsn1Field intermediateAsn1Field, String identifier) {
        asn1 = (Asn1Sequence) X509Translator.translateSingleIntermediateField(intermediateAsn1Field,
            Asn1SequenceFT.class, identifier, type);
        if (intermediateAsn1Field.getChildren().size() == 3) {
            tbsCertificate = TBSCertificate.getInstance(intermediateAsn1Field.getChildren().get(0), "tbsCertificate");
            signatureAlgorithm =
                AlgorithmIdentifier.getInstance(intermediateAsn1Field.getChildren().get(1), "signatureAlgorithm");
            signatureValue = (Asn1PrimitiveBitString) X509Translator.translateSingleIntermediateField(
                intermediateAsn1Field.getChildren().get(2), Asn1PrimitiveBitStringFT.class, "signatureValue", "");
            asn1.addChild(tbsCertificate.asn1);
            asn1.addChild(signatureAlgorithm.asn1);
            asn1.addChild(signatureValue);
        }

    }
}
