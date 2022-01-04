/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509;

import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1PrimitiveOctetString;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;
import de.rub.nds.asn1.translator.X509Translator;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1IntegerFT;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1PrimitiveOctetStringFT;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1SequenceFT;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * 
 * AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] KeyIdentifier OPTIONAL, authorityCertIssuer [1] GeneralNames
 * OPTIONAL, authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL }
 *
 * KeyIdentifier ::= OCTET STRING
 * 
 * CertificateSerialNumber ::= INTEGER
 * 
 */

public class AuthorityKeyIdentifier extends X509Model<Asn1Sequence> {

    private static final Logger LOGGER = LogManager.getLogger();

    public static final String OID = "2.5.29.35";

    private static final String type = "AuthorityKeyIdentifier";

    public Asn1PrimitiveOctetString keyIdentifier;
    public GeneralNames authorityCertIssuer;
    public Asn1Integer authorityCertSerialNumber;

    public static AuthorityKeyIdentifier getInstance(IntermediateAsn1Field intermediateAsn1Field, String identifier) {

        return new AuthorityKeyIdentifier(intermediateAsn1Field, identifier);
    }

    private AuthorityKeyIdentifier(IntermediateAsn1Field intermediateAsn1Field, String identifier) {

        asn1 = (Asn1Sequence) X509Translator.translateSingleIntermediateField(intermediateAsn1Field,
            Asn1SequenceFT.class, identifier, type);

        for (IntermediateAsn1Field interFieldChild : intermediateAsn1Field.getChildren()) {

            switch (interFieldChild.getTagNumber()) {

                case 0: // KeyIdentifier
                    keyIdentifier =
                        (Asn1PrimitiveOctetString) X509Translator.translateSingleIntermediateField(interFieldChild,
                            Asn1PrimitiveOctetStringFT.class, "keyIdentifier", "KeyIdentifier");
                    asn1.addChild(keyIdentifier);
                    break;

                case 1: // GeneralNames
                    authorityCertIssuer = GeneralNames.getInstance(interFieldChild, "authorityCertIssuer");
                    asn1.addChild(authorityCertIssuer.asn1);
                    break;

                case 2: // CertificateSerialNumber
                    authorityCertSerialNumber =
                        (Asn1Integer) X509Translator.translateSingleIntermediateField(interFieldChild,
                            Asn1IntegerFT.class, "authorityCertSerialNumber", "CertificateSerialNumber");
                    asn1.addChild(authorityCertSerialNumber);
                    break;

                default:
                    LOGGER.warn(
                        "Parser Error: AuthorityKeyIdentifier -> Default Case triggerd; no Parser defined for Tag Number: "
                            + interFieldChild.getTagNumber());
            }

        }
    }

}
