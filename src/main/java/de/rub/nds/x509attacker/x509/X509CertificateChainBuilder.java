/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.context.X509Context;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import de.rub.nds.x509attacker.x509.preparator.X509CertificatePreparator;
import java.util.List;

public class X509CertificateChainBuilder {

    public X509CertificateChainBuilder() {}

    /**
     * Builds a certificate chain from a list of certificate configs. The first certificate in the
     * chain is the leaf
     *
     * @param certificateConfigs
     * @return
     */
    public X509ChainCreationResult buildChain(List<X509CertificateConfig> certificateConfigs) {
        return buildChain(certificateConfigs.toArray(X509CertificateConfig[]::new));
    }

    /**
     * Builds a certificate chain from an array of certificate configs. The first certificate in the
     * chain is the leaf
     *
     * @param certificateConfigs
     * @return
     */
    public X509ChainCreationResult buildChain(X509CertificateConfig... certificateConfigs) {
        X509CertificateChain chain = new X509CertificateChain();
        X509Context context = new X509Context();
        for (int i = certificateConfigs.length - 1; i >= 0; i--) {
            X509CertificateConfig config = certificateConfigs[i];
            if (context.getSubject() != null) {
                config.setIssuer(context.getSubject());
            }
            X509Certificate certificate = new X509Certificate("certiciate_" + (i + 1), config);
            context.setConfig(config);
            X509Chooser chooser = new X509Chooser(config, context);
            X509CertificatePreparator preparator =
                    new X509CertificatePreparator(chooser, certificate);
            preparator.prepare();
            chain.addCertificate(0, certificate);
        }
        return new X509ChainCreationResult(chain, context);
    }
}
