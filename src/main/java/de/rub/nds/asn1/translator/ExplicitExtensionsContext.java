package de.rub.nds.asn1.translator;

import de.rub.nds.asn1.translator.contextcomponents.ParseNativeTypeContextComponent;
import de.rub.nds.asn1.translator.defaultcontextcomponentoptions.*;

public class ExplicitExtensionsContext extends Context {

    public static String NAME = "ExplicitExtensionsContext";

    private static final ContextComponent[] contextComponents = new ContextComponent[] {
        new ContextComponent("extensions", "Extensions", new ContextComponentOption<?>[] {new Asn1SequenceCCO(ExtensionsContext.NAME)}, false, false),
    };

    public ExplicitExtensionsContext() {
        super(contextComponents);
    }

    @Override
    public String getName() {
        return NAME;
    }
}
