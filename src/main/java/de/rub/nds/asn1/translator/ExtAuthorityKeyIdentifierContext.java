package de.rub.nds.asn1.translator;

import de.rub.nds.asn1.translator.defaultcontextcomponentoptions.*;

public class ExtAuthorityKeyIdentifierContext extends Context {

    public static String NAME = "ExtAuthorityKeyIdentifierContext";

    private static final ContextComponent[] contextComponents = new ContextComponent[] {
        new ContextComponent("authorityKeyIdentifier", "AuthorityKeyIdentifier", new ContextComponentOption<?>[] {new Asn1SequenceCCO(AuthorityKeyIdentifierContext.NAME)}, false, false),
    };

    public ExtAuthorityKeyIdentifierContext() {
        super(contextComponents);
    }

    @Override
    public String getName() {
        return NAME;
    }
}
