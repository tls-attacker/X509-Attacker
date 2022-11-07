/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.asn1.translator;

import de.rub.nds.asn1.translator.defaultcontextcomponentoptions.*;

public class CertificateContext extends Context {

    public static final String NAME = "CertificateContext";

    private static final ContextComponent[] contextComponents = new ContextComponent[]{
        new ContextComponent("tbsCertificate", "TBSCertificate",
        new ContextComponentOption<?>[]{new Asn1SequenceCCO(TBSCertificateContext.NAME)}, false, false),
        new ContextComponent("signatureAlgorithm", "AlgorithmIdentifier",
        new ContextComponentOption<?>[]{new Asn1SequenceCCO(AlgorithmIdentifierContext.NAME)}, false, false),
        new ContextComponent("signatureValue", "", new ContextComponentOption<?>[]{new Asn1PrimitiveBitStringCCO()},
        false, false)};

    public CertificateContext() {
        super(contextComponents);
    }

    @Override
    public String getName() {
        return NAME;
    }
}
