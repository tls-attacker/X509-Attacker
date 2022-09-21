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
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;
import de.rub.nds.asn1.translator.X509Translator;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1ObjectIdentifierFT;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1SequenceFT;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * PolicyInformation ::= SEQUENCE { policyIdentifier CertPolicyId, policyQualifiers SEQUENCE SIZE (1..MAX) OF
 * PolicyQualifierInfo OPTIONAL }
 *
 * CertPolicyId ::= OBJECT IDENTIFIER
 *
 */

public class PolicyInformation extends X509Model<Asn1Sequence> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final String type = "PolicyInformation";

    public Asn1ObjectIdentifier policyIdentifier; // CertPolicyId ::= OBJECT IDENTIFIER
    public PolicyQualifiers policyQualifiers;

    public static PolicyInformation getInstance(IntermediateAsn1Field intermediateAsn1Field, String identifier) {

        return new PolicyInformation(intermediateAsn1Field, identifier);
    }

    private PolicyInformation(IntermediateAsn1Field intermediateAsn1Field, String identifier) {

        asn1 = (Asn1Sequence) X509Translator.translateSingleIntermediateField(intermediateAsn1Field,
            Asn1SequenceFT.class, identifier, type);

        // PolicyIdentifier
        policyIdentifier = (Asn1ObjectIdentifier) X509Translator.translateSingleIntermediateField(
            intermediateAsn1Field.getChildren().get(0), Asn1ObjectIdentifierFT.class, "policyIdentifier", "");
        asn1.addChild(policyIdentifier);

        // PolicyQualifiers - can be optional
        if (intermediateAsn1Field.getChildren().size() == 2) {
            policyQualifiers =
                PolicyQualifiers.getInstance(intermediateAsn1Field.getChildren().get(1), "policyQualifiers");
            asn1.addChild(policyQualifiers.asn1);
        }
    }

}
