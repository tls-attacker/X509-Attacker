package de.rub.nds.asn1.translator;

import de.rub.nds.asn1.translator.contextcomponents.ParseNativeTypeContextComponent;
import de.rub.nds.asn1.translator.defaultcontextcomponentoptions.*;

public class TestEncapsulatingExtensionContext extends Context {

    public static String NAME = "TestParseX509ExtensionContext";

    private static final ContextComponent[] contextComponents = new ContextComponent[] {
        new ContextComponent("extnValue", "", new ContextComponentOption<?>[] {new Asn1EncapsulatingOctetStringCCO(ParseNativeTypesContext.NAME)}, false, false)
    };

    public TestEncapsulatingExtensionContext() {
        super(contextComponents);
    }

    @Override
    public String getName() {
        return NAME;
    }
}
