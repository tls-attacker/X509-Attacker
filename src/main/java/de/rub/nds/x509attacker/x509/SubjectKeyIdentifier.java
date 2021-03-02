/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509;

import de.rub.nds.asn1.model.Asn1PrimitiveOctetString;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;
import de.rub.nds.asn1.translator.X509Translator;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1PrimitiveOctetStringFT;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * 
 * SubjectKeyIdentifier ::= KeyIdentifier
 *
 * KeyIdentifier ::= OCTET STRING
 * 
 */
public class SubjectKeyIdentifier extends X509Model<Asn1PrimitiveOctetString> {

    private static final Logger LOGGER = LogManager.getLogger();

    public static final String OID = "2.5.29.14";
    private static final String type = "SubjectKeyIdentifier";

    public static SubjectKeyIdentifier getInstance(IntermediateAsn1Field intermediateAsn1Field, String identifier) {

        return new SubjectKeyIdentifier(intermediateAsn1Field, identifier);
    }

    private SubjectKeyIdentifier(IntermediateAsn1Field intermediateAsn1Field, String identifier) {
        // keyIdentifier
        asn1 = (Asn1PrimitiveOctetString) X509Translator.translateSingleIntermediateField(intermediateAsn1Field,
            Asn1PrimitiveOctetStringFT.class, identifier, type);
    }

}
