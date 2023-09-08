/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser;

import de.rub.nds.asn1.constants.TagClass;
import de.rub.nds.asn1.constants.UniversalTagNumber;
import de.rub.nds.asn1.parser.ParserHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import de.rub.nds.x509attacker.x509.model.CertificateSignatureAlgorithmIdentifier;
import de.rub.nds.x509attacker.x509.model.publickey.parameters.X509NullParameters;
import java.io.BufferedInputStream;

public class CertificateSignatureAlgorithmIdentifierParser
        extends X509ComponentContainerParser<CertificateSignatureAlgorithmIdentifier> {

    public CertificateSignatureAlgorithmIdentifierParser(
            X509Chooser chooser, CertificateSignatureAlgorithmIdentifier algorithmIdentifier) {
        super(chooser, algorithmIdentifier);
    }

    @Override
    protected void parseSubcomponents(BufferedInputStream inputStream) {
        ParserHelper.parseAsn1ObjectIdentifier(encodable.getAlgorithm(), inputStream);
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
                if (ParserHelper.canParse(
                        inputStream, TagClass.UNIVERSAL, UniversalTagNumber.NULL.getIntValue())) {
                    X509NullParameters nullParameters = new X509NullParameters("nullParameters");
                    encodable.setParameters(nullParameters);
                    nullParameters.getParser(chooser).parse(inputStream);
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
                X509NullParameters nullParameters = new X509NullParameters("nullParameters");
                encodable.setParameters(nullParameters);
                nullParameters.getParser(chooser).parse(inputStream);
                break;
            default:
                throw new UnsupportedOperationException("Encountered unknown signature algorithm");
        }
    }
}
