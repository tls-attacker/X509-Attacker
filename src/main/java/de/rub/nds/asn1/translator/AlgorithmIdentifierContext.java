package de.rub.nds.asn1.translator;


import de.rub.nds.asn1.translator.defaultcontextcomponentoptions.*;

public class AlgorithmIdentifierContext extends Context {

    public static String NAME = "AlgorithmIdentifierContext";

    private static final ContextComponent[] contextComponents = new ContextComponent[] {
        new ContextComponent("algorithm", "", new ContextComponentOption<?>[] {new Asn1ObjectIdentifierCCO()}, false, false),
        new ContextComponent("parameters", "", new ContextComponentOption<?>[] {new Asn1NullCCO()}, true, false) //TODO: laut RFC Type ANY, hier nur NULL abgedeckt!
    };

    public AlgorithmIdentifierContext() {
        super(contextComponents);
    }

    @Override
    public String getName() {
        return NAME;
    }
}
