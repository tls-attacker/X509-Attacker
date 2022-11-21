/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509.preparator.publickey;

import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.x509.base.publickey.RsaPublicKey;
import de.rub.nds.x509attacker.x509.preparator.X509ComponentPreparator;

public class RsaPublicKeyPreparator extends X509ComponentPreparator<RsaPublicKey> {

    public RsaPublicKeyPreparator(RsaPublicKey instance, X509CertificateConfig config) {
        super(instance, config);
    }

    
    @Override
    protected byte[] encodeContent() {
        instance.getModulus().setValue(config.getRsaModulus());
        instance.getPublicExponent().setValue(config.getRsaPublicKey());
        instance.getGenericPreparator().prepare();
        return instance.getEncodedChildren().getValue();
    }

}
