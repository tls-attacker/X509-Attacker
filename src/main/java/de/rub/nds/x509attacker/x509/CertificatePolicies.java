/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509;

import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;
import de.rub.nds.asn1.translator.X509Translator;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1SequenceFT;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
 *
 */

public class CertificatePolicies extends X509Model<Asn1Sequence> {

    private static final Logger LOGGER = LogManager.getLogger();

    public static final String OID = "2.5.29.32";

    private static final String type = "CertificatePolicies";

    public List<PolicyInformation> policyInformation;

    public static CertificatePolicies getInstance(IntermediateAsn1Field intermediateAsn1Field, String identifier) {

        return new CertificatePolicies(intermediateAsn1Field, identifier);
    }

    private CertificatePolicies(IntermediateAsn1Field intermediateAsn1Field, String identifier) {

        asn1 = (Asn1Sequence) X509Translator.translateSingleIntermediateField(intermediateAsn1Field,
            Asn1SequenceFT.class, identifier, type);

        policyInformation = new LinkedList<>();
        int index = 0;
        for (IntermediateAsn1Field interFieldChild : intermediateAsn1Field.getChildren()) {
            policyInformation.add(PolicyInformation.getInstance(interFieldChild, "policyInformation" + index++));
            asn1.addChild(policyInformation.get(policyInformation.size() - 1).asn1);
        }
    }

}
