package de.rub.nds.asn1.translator;

import de.rub.nds.asn1.translator.contextcomponents.ParseNativeTypeContextComponent;
import de.rub.nds.asn1.translator.defaultcontextcomponentoptions.*;

public class ExtensionContext extends Context {

    public static String NAME = "ExtensionContext";

    private static final ContextComponent[] contextComponents = new ContextComponent[] {
        new ContextComponent("extnID", "", new ContextComponentOption<?>[] {new Asn1ObjectIdentifierCCO()}, false, false),
        new ContextComponent("critical", "", new ContextComponentOption<?>[] {new Asn1BooleanCCO()}, true, false),
        new ContextComponent("extnValue", "", new ContextComponentOption<?>[] {new Asn1EncapsulatingOctetStringCCO(ParseNativeTypesContext.NAME)}, false, false)
    };

    public ExtensionContext() {
        super(contextComponents);
    }

    @Override
    public String getName() {
        return NAME;
    }
}
