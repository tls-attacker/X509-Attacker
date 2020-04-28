package de.rub.nds.asn1.translator;

import de.rub.nds.asn1.translator.contextcomponents.ParseNativeTypeContextComponent;
import de.rub.nds.asn1.translator.defaultcontextcomponentoptions.*;

public class CertificateOuterContext extends Context {

    public static String NAME = "CertificateOuterContext";

    private static final ContextComponent[] contextComponents = new ContextComponent[] {
        new ContextComponent("certificate", "Certificate", new ContextComponentOption<?>[] {new Asn1SequenceCCO(CertificateContext.NAME)}, false, false)
    };

    public CertificateOuterContext() {
        super(contextComponents);
    }

    @Override
    public String getName() {
        return NAME;
    }
}
