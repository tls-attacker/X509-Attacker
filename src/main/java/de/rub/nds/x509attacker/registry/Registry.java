/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.registry;

import de.rub.nds.asn1.encoder.Asn1TypeRegister;
import de.rub.nds.asn1.encoder.typeprocessors.DefaultX509TypeProcessor;
import de.rub.nds.asn1.encoder.typeprocessors.SubjectPublicKeyInfoTypeProcessor;
import de.rub.nds.asn1.model.Asn1PseudoType;
import de.rub.nds.asn1.model.KeyInfo;
import de.rub.nds.asn1.model.SignatureInfo;
import de.rub.nds.asn1.parser.contentunpackers.ContentUnpackerRegister;
import de.rub.nds.asn1.parser.contentunpackers.DefaultContentUnpacker;
import de.rub.nds.asn1.parser.contentunpackers.PrimitiveBitStringUnpacker;
import de.rub.nds.asn1.translator.AlgorithmIdentifierContext;
import de.rub.nds.asn1.translator.AttributeTypeAndValueContext;
import de.rub.nds.asn1.translator.AuthorityKeyIdentifierContext;
import de.rub.nds.asn1.translator.CertificateContext;
import de.rub.nds.asn1.translator.CertificateOuterContext;
import de.rub.nds.asn1.translator.ContextRegister;
import de.rub.nds.asn1.translator.ExplicitExtensionsContext;
import de.rub.nds.asn1.translator.ExplicitVersionContext;
import de.rub.nds.asn1.translator.ExtAuthorityKeyIdentifierContext;
import de.rub.nds.asn1.translator.ExtKeyUsageContext;
import de.rub.nds.asn1.translator.ExtensionContext;
import de.rub.nds.asn1.translator.ExtensionsContext;
import de.rub.nds.asn1.translator.NameContext;
import de.rub.nds.asn1.translator.ParseNativeTypesContext;
import de.rub.nds.asn1.translator.RelativeDistinguishedNameContext;
import de.rub.nds.asn1.translator.SubjectPublicKeyInfoContext;
import de.rub.nds.asn1.translator.TBSCertificateContext;
import de.rub.nds.asn1.translator.TestExtensionsContext;
import de.rub.nds.asn1.translator.ValidityContext;
import de.rub.nds.asn1tool.Asn1Tool;
import de.rub.nds.asn1tool.xmlparser.JaxbClassList;
import de.rub.nds.x509attacker.x509.X509Certificate;
import de.rub.nds.x509attacker.x509.X509CertificateChain;

public class Registry {

    private static Registry instance = null;

    /**
     * Private constructor for singleton.
     */
    private Registry() {
        registerXmlClasses();
        registerTypes();
        registerContexts();
        registerContentUnpackers();
    }

    /**
     * Singleton getInstance() method.
     *
     * @return An instance of Asn1AnyTypeRegister.
     */
    public static Registry getInstance() {
        if (instance == null) {
            instance = new Registry();
        }
        return instance;
    }

    private void registerXmlClasses() {
        JaxbClassList jaxbClassList = JaxbClassList.getInstance();
        jaxbClassList.addClasses(Asn1Tool.getAsn1ToolJaxbClasses());
        jaxbClassList.addClasses(Asn1PseudoType.class, SignatureInfo.class, KeyInfo.class, X509CertificateChain.class,
            X509Certificate.class);
    }

    private void registerTypes() {
        Asn1TypeRegister asn1TypeRegister = Asn1TypeRegister.getInstance();
        asn1TypeRegister.setDefaultTypeProcessorClass(DefaultX509TypeProcessor.class);
        asn1TypeRegister.register("SubjectPublicKeyInfo", SubjectPublicKeyInfoTypeProcessor.class);
    }

    private void registerContexts() {
        ContextRegister contextRegister = ContextRegister.getInstance();
        contextRegister.registerContext(ParseNativeTypesContext.NAME, ParseNativeTypesContext.class);
        contextRegister.registerContext(AlgorithmIdentifierContext.NAME, AlgorithmIdentifierContext.class);
        contextRegister.registerContext(AttributeTypeAndValueContext.NAME, AttributeTypeAndValueContext.class);
        contextRegister.registerContext(CertificateContext.NAME, CertificateContext.class);
        contextRegister.registerContext(CertificateOuterContext.NAME, CertificateOuterContext.class);
        contextRegister.registerContext(ExplicitExtensionsContext.NAME, ExplicitExtensionsContext.class);
        contextRegister.registerContext(ExtensionContext.NAME, ExtensionContext.class);
        contextRegister.registerContext(ExtensionsContext.NAME, ExtensionsContext.class);
        contextRegister.registerContext(NameContext.NAME, NameContext.class);
        contextRegister.registerContext(RelativeDistinguishedNameContext.NAME, RelativeDistinguishedNameContext.class);
        contextRegister.registerContext(SubjectPublicKeyInfoContext.NAME, SubjectPublicKeyInfoContext.class);
        contextRegister.registerContext(TBSCertificateContext.NAME, TBSCertificateContext.class);
        contextRegister.registerContext(ValidityContext.NAME, ValidityContext.class);
        contextRegister.registerContext(ExplicitVersionContext.NAME, ExplicitVersionContext.class);

        // Extensions
        contextRegister.registerContext(ExtKeyUsageContext.NAME, ExtKeyUsageContext.class);
        contextRegister.registerContext(ExtAuthorityKeyIdentifierContext.NAME, ExtAuthorityKeyIdentifierContext.class);
        contextRegister.registerContext(AuthorityKeyIdentifierContext.NAME, AuthorityKeyIdentifierContext.class);

        // For Testing the Extension only
        contextRegister.registerContext(TestExtensionsContext.NAME, TestExtensionsContext.class);

    }

    private void registerContentUnpackers() {
        ContentUnpackerRegister contentUnpackerRegister = ContentUnpackerRegister.getInstance();
        contentUnpackerRegister.registerContentUnpacker(new DefaultContentUnpacker());
        contentUnpackerRegister.registerContentUnpacker(new PrimitiveBitStringUnpacker());
    }
}
