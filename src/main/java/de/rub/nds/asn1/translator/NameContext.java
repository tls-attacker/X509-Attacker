package de.rub.nds.asn1.translator;


import de.rub.nds.asn1.translator.defaultcontextcomponentoptions.*;

public class NameContext extends Context {

    public static String NAME = "NameContext";

    private static final ContextComponent[] contextComponents = new ContextComponent[] {
        new ContextComponent("relativeDistinguishedName", "RelativeDistinguishedName", new ContextComponentOption<?>[] {new Asn1SetCCO(RelativeDistinguishedNameContext.NAME)}, false, true)
    };

    public NameContext() {
        super(contextComponents);
    }

    @Override
    public String getName() {
        return NAME;
    }
}
