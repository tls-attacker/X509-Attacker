/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509.extensions;

import de.rub.nds.x509attacker.x509.extensions.ExtKeyUsage;
import de.rub.nds.x509attacker.x509.extensions.AuthorityKeyIdentifier;
import de.rub.nds.asn1.model.Asn1EncapsulatingOctetString;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;
import de.rub.nds.asn1.translator.X509Translator;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1EncapsulatingOctetStringFT;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 *
 * extnValue OCTET STRING -- contains the DER encoding of an ASN.1 value -- corresponding to the extension type
 * identified -- by extnID
 *
 */
public class ExtnValue extends X509Model<Asn1EncapsulatingOctetString> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final String type = "ExtnValue";

    public X509Model extensionValue;

    public static ExtnValue getInstance(IntermediateAsn1Field intermediateAsn1Field, String identifier, String oid) {

        return new ExtnValue(intermediateAsn1Field, identifier, oid);

    }

    private ExtnValue(IntermediateAsn1Field intermediateAsn1Field, String identifier, String oid) {
        asn1 = (Asn1EncapsulatingOctetString) X509Translator.translateSingleIntermediateField(intermediateAsn1Field,
            Asn1EncapsulatingOctetStringFT.class, identifier, type);

        switch (oid) {

            case AuthorityKeyIdentifier.OID:
                extensionValue = AuthorityKeyIdentifier.getInstance(intermediateAsn1Field.getChildren().get(0),
                    "authorityKeyIdentifier");
                asn1.addChild(extensionValue.asn1);
                break;

            case SubjectKeyIdentifier.OID:
                extensionValue = SubjectKeyIdentifier.getInstance(intermediateAsn1Field.getChildren().get(0),
                    "subjectKeyIdentifier");
                asn1.addChild(extensionValue.asn1);
                break;

            case KeyUsage.OID:
                extensionValue = KeyUsage.getInstance(intermediateAsn1Field.getChildren().get(0), "keyUsage");
                asn1.addChild(extensionValue.asn1);
                break;

            case BasicConstraints.OID:
                extensionValue =
                    BasicConstraints.getInstance(intermediateAsn1Field.getChildren().get(0), "basicConstraints");
                asn1.addChild(extensionValue.asn1);
                break;

            case ExtKeyUsage.OID:
                extensionValue = ExtKeyUsage.getInstance(intermediateAsn1Field.getChildren().get(0), "extKeyUsage");
                asn1.addChild(extensionValue.asn1);
                break;

            case CertificatePolicies.OID:
                extensionValue =
                    CertificatePolicies.getInstance(intermediateAsn1Field.getChildren().get(0), "certificatePolicies");
                asn1.addChild(extensionValue.asn1);
                break;

            case CRLDistributionPoints.OID:
                extensionValue = CRLDistributionPoints.getInstance(intermediateAsn1Field.getChildren().get(0),
                    "crlDistributionPoints");
                asn1.addChild(extensionValue.asn1);
                break;

            case AuthorityInfoAccess.OID:
                extensionValue =
                    AuthorityInfoAccess.getInstance(intermediateAsn1Field.getChildren().get(0), "authorityInfoAccess");
                asn1.addChild(extensionValue.asn1);
                break;

            case "2.5.29.17": // subjectAltNAme :== GeneralNames
                extensionValue = GeneralNames.getInstance(intermediateAsn1Field.getChildren().get(0), "subjectAltNAme");
                asn1.addChild(extensionValue.asn1);
                break;

            case signedCertificateTimestampList.OID:
                extensionValue = signedCertificateTimestampList.getInstance(intermediateAsn1Field.getChildren().get(0),
                    "signedCertificateTimestampList");
                asn1.addChild(extensionValue.asn1);
                break;

            default:
                LOGGER.warn(
                    "Parser Error: ExtnValue -> Default Case triggerd; no Parser defined for Extension OID: " + oid);
                break;

        }

    }

}
