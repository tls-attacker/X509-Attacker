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
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * 
 * AuthorityInfoAcessSyntax :== SEQUENCE SIZE (1..MAX) OF AccessDescription
 * 
 */

public class AuthorityInfoAccess extends X509Model<Asn1Sequence> {

    private static final Logger LOGGER = LogManager.getLogger();

    public static final String OID = "1.3.6.1.5.5.7.1.1";

    private static final String type = "AuthorityInfoAcess";

    public List<AccessDescription> accessDescription;

    public static AuthorityInfoAccess getInstance(IntermediateAsn1Field intermediateAsn1Field, String identifier) {

        return new AuthorityInfoAccess(intermediateAsn1Field, identifier);
    }

    private AuthorityInfoAccess(IntermediateAsn1Field intermediateAsn1Field, String identifier) {

        asn1 = (Asn1Sequence) X509Translator.translateSingleIntermediateField(intermediateAsn1Field,
            Asn1SequenceFT.class, identifier, type);

        accessDescription = new LinkedList<>();
        int index = 0;
        for (IntermediateAsn1Field interFieldChild : intermediateAsn1Field.getChildren()) {
            accessDescription.add(AccessDescription.getInstance(interFieldChild, "accessDescription" + index++));
            asn1.addChild(accessDescription.get(accessDescription.size() - 1).asn1);
        }
    }

}
