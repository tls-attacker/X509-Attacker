package de.rub.nds.asn1.translator;


import de.rub.nds.asn1.translator.defaultcontextcomponentoptions.*;

public class AttributeTypeAndValueContext extends Context {

    public static String NAME = "AttributeTypeAndValueContext";

    private static final ContextComponent[] contextComponents = new ContextComponent[] {
        new ContextComponent("type", "AttributeType", new ContextComponentOption<?>[] {new Asn1ObjectIdentifierCCO()}, false, false),
        //TODO: lauft RFC 5280 Kapitel 4.1.2.4.  Issuer: kann hier einer von 5 String Typen vorkommen
        new ContextComponent("value", "AttributeValue", new ContextComponentOption<?>[] {new Asn1PrimitivePrintableStringCCO(), new Asn1PrimitiveUtf8StringCCO()}, false, false)                  
    };

    public AttributeTypeAndValueContext() {
        super(contextComponents);
    }

    @Override
    public String getName() {
        return NAME;
    }
}
