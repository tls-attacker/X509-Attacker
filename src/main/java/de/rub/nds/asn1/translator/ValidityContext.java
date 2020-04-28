package de.rub.nds.asn1.translator;


import de.rub.nds.asn1.translator.defaultcontextcomponentoptions.*;

public class ValidityContext extends Context {

    public static String NAME = "ValidityContext";

    private static final ContextComponent[] contextComponents = new ContextComponent[] {
        new ContextComponent("notBefore", "Time", new ContextComponentOption<?>[] {new Asn1PrimitiveUtcTimeCCO(), new Asn1PrimitiveGeneralizedTimeCCO()}, false, false),
        new ContextComponent("notAfter", "Time", new ContextComponentOption<?>[] {new Asn1PrimitiveUtcTimeCCO(), new Asn1PrimitiveGeneralizedTimeCCO()}, false, false)
    };

    public ValidityContext() {
        super(contextComponents);
    }

    @Override
    public String getName() {
        return NAME;
    }
}
