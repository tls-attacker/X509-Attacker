package de.rub.nds.asn1.translator;

import de.rub.nds.asn1.translator.contextcomponents.ParseNativeTypeContextComponent;
import de.rub.nds.asn1.translator.defaultcontextcomponentoptions.*;

public class ExplicitVersionContext extends Context {

    public static String NAME = "ExplicitVersionContext";

    private static final ContextComponent[] contextComponents = new ContextComponent[] {
        new ContextComponent("version", "Version", new ContextComponentOption<?>[] {new Asn1IntegerCCO()}, false, false),
    };

    public ExplicitVersionContext() {
        super(contextComponents);
    }

    @Override
    public String getName() {
        return NAME;
    }
}
