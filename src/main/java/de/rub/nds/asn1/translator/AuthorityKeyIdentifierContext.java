/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.asn1.translator;

import de.rub.nds.asn1.translator.defaultcontextcomponentoptions.*;

public class AuthorityKeyIdentifierContext extends Context {

    public static String NAME = "AuthorityKeyIdentifierInnerContext";

    private static final ContextComponent[] contextComponents = new ContextComponent[] {
        new ContextComponent("keyIdentifier", "AuthorityKeyIdentifier",
            new ContextComponentOption<?>[] { new Asn1PrimitiveOctetStringCCO() }, true, false),
        new ContextComponent("authorityCertIssuer", "AuthorityKeyIdentifier",
            new ContextComponentOption<?>[] { new Asn1SequenceCCO(TBSCertificateContext.NAME) }, true, false),
        new ContextComponent("authorityCertSerialNumber", "AuthorityKeyIdentifier",
            new ContextComponentOption<?>[] { new Asn1SequenceCCO(TBSCertificateContext.NAME) }, true, false) };

    public AuthorityKeyIdentifierContext() {
        super(contextComponents);
    }

    @Override
    public String getName() {
        return NAME;
    }
}
