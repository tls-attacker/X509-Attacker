package de.rub.nds.asn1.translator;

import de.rub.nds.asn1.translator.contextcomponents.ParseNativeTypeContextComponent;
import de.rub.nds.asn1.translator.defaultcontextcomponentoptions.*;

public class TestExtensionsContext extends Context {

    public static String NAME = "TestExtensionsContext";

    private static final ContextComponent[] contextComponents = new ContextComponent[] {
        new ContextComponent("explicitExtensions", "", new ContextComponentOption<?>[] {new Asn1ExplicitCCO(ExplicitExtensionsContext.NAME)}, false, false)
    };

    public TestExtensionsContext() {
        super(contextComponents);
    }

    @Override
    public String getName() {
        return NAME;
    }
}
