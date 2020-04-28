package de.rub.nds.asn1.translator;

import de.rub.nds.asn1.translator.contextcomponents.ParseNativeTypeContextComponent;
import de.rub.nds.asn1.translator.defaultcontextcomponentoptions.*;

public class TBSCertificateContext extends Context {

    public static String NAME = "TBSCertificateContext";

    private static final ContextComponent[] contextComponents = new ContextComponent[] {
        new ContextComponent("explicitVersion", "", new ContextComponentOption<?>[] {new Asn1ExplicitCCO(ExplicitVersionContext.NAME)}, false, false),
        new ContextComponent("serialNumber", "CertificateSerialNumber", new ContextComponentOption<?>[] {new Asn1IntegerCCO()}, false, false),
        new ContextComponent("signature", "AlgorithmIdentifier", new ContextComponentOption<?>[] {new Asn1SequenceCCO(AlgorithmIdentifierContext.NAME)}, false, false),
        new ContextComponent("issuer", "Name", new ContextComponentOption<?>[] {new Asn1SequenceCCO(NameContext.NAME)}, false, false),
        new ContextComponent("validity", "Validity", new ContextComponentOption<?>[] {new Asn1SequenceCCO(ValidityContext.NAME)}, false, false),
        new ContextComponent("subject", "Name", new ContextComponentOption<?>[] {new Asn1SequenceCCO(NameContext.NAME)}, false, false),
        new ContextComponent("subjectPublicKeyInfo", "SubjectPublicKeyInfo", new ContextComponentOption<?>[] {new Asn1SequenceCCO(SubjectPublicKeyInfoContext.NAME)}, false, false),
        //TODO: laut RFC können die folgenden 2 Felder noch optional vorkommen
        //new ContextComponent("issuerUniqueID", "UniqueIdentifier", new ContextComponentOption<?>[] {new Asn1SequenceCCO(SubjectPublicKeyInfoContext.NAME)}, true, false),
        //new ContextComponent("subjectUniqueID", "UniqueIdentifier", new ContextComponentOption<?>[] {new Asn1SequenceCCO(SubjectPublicKeyInfoContext.NAME)}, true, false),
        new ContextComponent("explicitExtensions", "", new ContextComponentOption<?>[] {new Asn1ExplicitCCO(ExplicitExtensionsContext.NAME)}, false, false)
    };

    public TBSCertificateContext() {
        super(contextComponents);
    }

    @Override
    public String getName() {
        return NAME;
    }
}
