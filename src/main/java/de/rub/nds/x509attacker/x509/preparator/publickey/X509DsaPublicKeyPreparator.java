/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator.publickey;

import de.rub.nds.asn1.preparator.Asn1PreparatorHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.publickey.X509DsaPublicKey;
import de.rub.nds.x509attacker.x509.preparator.X509Asn1FieldPreparator;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class X509DsaPublicKeyPreparator extends X509Asn1FieldPreparator<X509DsaPublicKey> {

    private static final Logger LOGGER = LogManager.getLogger();

    public X509DsaPublicKeyPreparator(X509DsaPublicKey instance, X509Chooser chooser) {
        super(chooser, instance);
    }

    @Override
    protected byte[] encodeContent() {
        BigInteger publicKey =
                chooser.getSubjectDsaGenerator()
                        .modPow(
                                chooser.getConfig().getDefaultIssuerDsaPrivateKey(),
                                chooser.getSubjectDsaPrimeP());
        LOGGER.debug("Computed dsa public key as: {}", publicKey);
        Asn1PreparatorHelper.prepareField(field, publicKey);
        return publicKey.toByteArray();
    }
}
