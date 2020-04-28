package de.rub.nds.asn1.translator;

import de.rub.nds.asn1.translator.defaultcontextcomponentoptions.*;

public class ExtKeyUsageContext extends Context {

    public static String NAME = "ExtKeyUsageContext";

    private static final ContextComponent[] contextComponents = new ContextComponent[] {
        new ContextComponent("keyUsage", "KeyUsage", new ContextComponentOption<?>[] {new Asn1PrimitiveBitStringCCO()}, false, false),
    };

    public ExtKeyUsageContext() {
        super(contextComponents);
    }

    @Override
    public String getName() {
        return NAME;
    }
}
