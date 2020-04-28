package de.rub.nds.asn1.translator;


import de.rub.nds.asn1.translator.defaultcontextcomponentoptions.*;

public class RelativeDistinguishedNameContext extends Context {

    public static String NAME = "RelativeDistinguishedNameContext";

    private static final ContextComponent[] contextComponents = new ContextComponent[] {
        new ContextComponent("attributeTypeAndValue", "AttributeTypeAndValue", new ContextComponentOption<?>[] {new Asn1SequenceCCO(AttributeTypeAndValueContext.NAME)}, false, true)
    };

    public RelativeDistinguishedNameContext() {
        super(contextComponents);
    }

    @Override
    public String getName() {
        return NAME;
    }
}
