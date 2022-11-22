/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.x509.base.X509Certificate;
import org.junit.jupiter.api.Test;

public class X509CertificatePreparatorTest {

    private X509CertificatePreparator instance;

    /**
     * Test of prepareContent method, of class X509CertificatePreparator.
     */
    @Test
    public void testPrepareContent() {
        X509CertificateConfig config = new X509CertificateConfig();
        X509Certificate x509Certificate = new X509Certificate("leafCertificate", config);
        instance = new X509CertificatePreparator(x509Certificate, config);

        instance.prepare();
        System.out.println(ArrayConverter.bytesToHexString(x509Certificate.getGenericSerializer().serialize()));

    }

}
