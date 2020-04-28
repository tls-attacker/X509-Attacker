package de.rub.nds.asn1.translator;

import de.rub.nds.asn1.translator.contextcomponents.ParseNativeTypeContextComponent;
import de.rub.nds.asn1.translator.defaultcontextcomponentoptions.*;

public class ExtensionsContext extends Context {

    public static String NAME = "ExtensionsContext";

    private static final ContextComponent[] contextComponents = new ContextComponent[] {
        new ContextComponent("extension", "Extension", new ContextComponentOption<?>[] {new Asn1SequenceCCO(ExtensionContext.NAME)}, false, true),
    };

    public ExtensionsContext() {
        super(contextComponents);
    }

    @Override
    public String getName() {
        return NAME;
    }
}
