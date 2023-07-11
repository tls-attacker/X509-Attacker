/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser;

import java.io.BufferedInputStream;

import de.rub.nds.asn1.constants.TagClass;
import de.rub.nds.asn1.constants.UniversalTagNumber;
import de.rub.nds.asn1.model.Asn1Null;
import de.rub.nds.asn1.parser.ParserHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import de.rub.nds.x509attacker.x509.model.CertificateSignatureAlgorithmIdentifier;

public class CertificateSignatureAlgorithmIdentifierParser
        extends X509ComponentContainerParser<CertificateSignatureAlgorithmIdentifier> {

    public CertificateSignatureAlgorithmIdentifierParser(
            X509Chooser chooser, CertificateSignatureAlgorithmIdentifier algorithmIdentifier) {
        super(chooser, algorithmIdentifier);
    }

    @Override
    protected void parseSubcomponents(BufferedInputStream inputStream) {
        ParserHelper.parseAsn1ObjectIdentifier(encodable.getAlgorithm(), inputStream);

        Asn1Null nullField = new Asn1Null("null");

        switch (X509SignatureAlgorithm.decodeFromOidBytes(
                encodable.getAlgorithm().getValueAsOid().getEncoded())) {
            case DSA_WITH_SHA1:
            case DSA_WITH_SHA224:
            case DSA_WITH_SHA256:
            case DSA_WITH_SHA384:
            case DSA_WITH_SHA512:
                // No parameters, not even null
                break;
            case ECDSA_WITH_SHA1:
            case ECDSA_WITH_SHA224:
            case ECDSA_WITH_SHA256:
            case ECDSA_WITH_SHA384:
            case ECDSA_WITH_SHA512:
                if (ParserHelper.canParse(inputStream, TagClass.UNIVERSAL, UniversalTagNumber.NULL.getIntValue())) {
                    encodable.setParameters(nullField);
                    ParserHelper.parseAsn1Null(nullField, inputStream);
                }
                break;
            case MD2_WITH_RSA_ENCRYPTION:
            case MD4_WITH_RSA_ENCRYPTION:
            case MD5_WITH_RSA_ENCRYPTION:
            case SHA1_WITH_RSA_ENCRYPTION:
            case SHA224_WITH_RSA_ENCRYPTION:
            case SHA256_WITH_RSA_ENCRYPTION:
            case SHA384_WITH_RSA_ENCRYPTION:
            case SHA512_WITH_RSA_ENCRYPTION:
                encodable.setParameters(nullField);
                ParserHelper.parseAsn1Null(nullField, inputStream);
                break;
            default:
                encodable.setParameters(nullField);
                ParserHelper.parseAsn1Null(nullField, inputStream);
                break;
        }
    }
}
