/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.context.X509Context;
import de.rub.nds.x509attacker.x509.base.X509Certificate;
import de.rub.nds.x509attacker.x509.base.X509CertificateChain;
import de.rub.nds.x509attacker.x509.preparator.X509CertificatePreparator;
import java.util.List;

public class X509CertificateChainBuidler {

    public X509CertificateChainBuidler() {}

    public X509CertificateChain buildChain(List<X509CertificateConfig> certificateConfigs) {
        return buildChain(certificateConfigs.toArray(X509CertificateConfig[]::new));
    }

    public X509CertificateChain buildChain(X509CertificateConfig... certificateConfigs) {
        X509CertificateChain chain = new X509CertificateChain();
        X509Context context = new X509Context();
        int counter = 1;
        for (X509CertificateConfig config : certificateConfigs) {
            if (context.getSubject() != null) {
                config.setIssuer(context.getSubject());
            }
            X509Certificate certificate = new X509Certificate("certiciate_" + counter, config);
            context.setConfig(config);
            X509Chooser chooser = new X509Chooser(config, context);
            X509CertificatePreparator preparator =
                    new X509CertificatePreparator(chooser, certificate);
            preparator.prepare();
            chain.addCertificate(certificate);
            counter++;
        }
        return chain;
    }
}
