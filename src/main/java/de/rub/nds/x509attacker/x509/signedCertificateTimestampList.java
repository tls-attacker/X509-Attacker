/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
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
 * SignedCertificateTimestampList ::= OCTET STRING
 *
 */

public class signedCertificateTimestampList extends X509Model<Asn1PrimitiveOctetString> {

    private static final Logger LOGGER = LogManager.getLogger();

    public static final String OID = "1.3.6.1.4.1.11129.2.4.2";

    private static final String type = "SignedCertificateTimestamp";

    public static signedCertificateTimestampList getInstance(IntermediateAsn1Field intermediateAsn1Field,
        String identifier) {

        return new signedCertificateTimestampList(intermediateAsn1Field, identifier);
    }

    private signedCertificateTimestampList(IntermediateAsn1Field intermediateAsn1Field, String identifier) {
        asn1 = (Asn1PrimitiveOctetString) X509Translator.translateSingleIntermediateField(intermediateAsn1Field,
            Asn1PrimitiveOctetStringFT.class, identifier, type);
    }

}
