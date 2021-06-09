/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509;

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
 * ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
 * 
 * KeyPurposeId ::= OBJECT IDENTIFIER
 * 
 */

public class ExtKeyUsage extends X509Model<Asn1Sequence> {

    private static final Logger LOGGER = LogManager.getLogger();

    public static final String OID = "2.5.29.37";

    private static final String type = "ExtKeyUsage";

    public List<Asn1ObjectIdentifier> keyPurposeID;

    public static ExtKeyUsage getInstance(IntermediateAsn1Field intermediateAsn1Field, String identifier) {

        return new ExtKeyUsage(intermediateAsn1Field, identifier);
    }

    private ExtKeyUsage(IntermediateAsn1Field intermediateAsn1Field, String identifier) {

        asn1 = (Asn1Sequence) X509Translator.translateSingleIntermediateField(intermediateAsn1Field,
            Asn1SequenceFT.class, identifier, type);

        keyPurposeID = new LinkedList<>();
        int index = 0;
        for (IntermediateAsn1Field interFieldChild : intermediateAsn1Field.getChildren()) {
            keyPurposeID.add((Asn1ObjectIdentifier) X509Translator.translateSingleIntermediateField(interFieldChild,
                Asn1ObjectIdentifierFT.class, "keyPurposeID" + index++, ""));
            asn1.addChild(keyPurposeID.get(keyPurposeID.size() - 1));
        }
    }

}
