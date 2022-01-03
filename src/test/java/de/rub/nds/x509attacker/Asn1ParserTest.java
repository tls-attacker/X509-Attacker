/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.encoder.Asn1TypeRegister;
import de.rub.nds.asn1.encoder.typeprocessors.DefaultX509TypeProcessor;
import de.rub.nds.asn1.encoder.typeprocessors.SubjectPublicKeyInfoTypeProcessor;
import de.rub.nds.asn1.model.Asn1PseudoType;
import de.rub.nds.asn1.model.KeyInfo;
import de.rub.nds.asn1.model.SignatureInfo;
import de.rub.nds.asn1.parser.Asn1Parser;
import de.rub.nds.asn1.parser.ParserException;
import de.rub.nds.asn1.parser.contentunpackers.ContentUnpackerRegister;
import de.rub.nds.asn1.parser.contentunpackers.DefaultContentUnpacker;
import de.rub.nds.asn1.parser.contentunpackers.PrimitiveBitStringUnpacker;
import de.rub.nds.asn1.translator.*;
import de.rub.nds.asn1.translator.TestExtensionsContext;
import de.rub.nds.asn1tool.Asn1Tool;
import de.rub.nds.asn1tool.xmlparser.JaxbClassList;
import de.rub.nds.x509attacker.registry.Registry;
import java.util.List;
import org.junit.Test;

/**
 *
 * @author josh
 */
public class Asn1ParserTest {

    @Test
    public void testAsn1Parser() throws ParserException {
        System.out.println("Test Asn1 Parser");

        try {
            Registry.getInstance();

            byte[] certificateContent;

            /*
             * //Test von Encapsulated BitStrings //certificateContent = hexStringToByteArray("040403020186");
             * certificateContent = hexStringToByteArray("04050303070400"); Asn1Parser asn1Parser = new
             * Asn1Parser(certificateContent, false); List<Asn1Encodable> asn1Encodables =
             * asn1Parser.parse(TestEncapsulatingExtensionContext.NAME);
             */

            // Test von ExtensionContent only/ Unterscheiden zwischen Boolean und octedString
            byte[] extensionContent =
                hexStringToByteArray("0603551D23041830168014BBAF7E023DFAA6F13C848EADEE3898ECD93232D4");
            Asn1Parser asn1Parser2 = new Asn1Parser(extensionContent, false);
            List<Asn1Encodable> asn1Encodables2 = asn1Parser2.parse(ExtensionContext.NAME);

            System.out.println("Done.");
        } catch (ParserException e) {
            throw new ParserException(e);
        }

    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    private static void registerXmlClasses() {
        JaxbClassList jaxbClassList = JaxbClassList.getInstance();
        jaxbClassList.addClasses(Asn1Tool.getAsn1ToolJaxbClasses());
        jaxbClassList.addClasses(Asn1PseudoType.class, SignatureInfo.class, KeyInfo.class);
    }

    private static void registerTypes() {
        Asn1TypeRegister asn1TypeRegister = Asn1TypeRegister.getInstance();
        asn1TypeRegister.setDefaultTypeProcessorClass(DefaultX509TypeProcessor.class);
        asn1TypeRegister.register("SubjectPublicKeyInfo", SubjectPublicKeyInfoTypeProcessor.class);
    }

    private static void registerContexts() {
        ContextRegister contextRegister = ContextRegister.getInstance();
        contextRegister.registerContext(TestEncapsulatingExtensionContext.NAME,
            TestEncapsulatingExtensionContext.class);
        contextRegister.registerContext(ExtensionContext.NAME, ExtensionContext.class);

    }

    private static void registerContentUnpackers() {
        ContentUnpackerRegister contentUnpackerRegister = ContentUnpackerRegister.getInstance();
        contentUnpackerRegister.registerContentUnpacker(new DefaultContentUnpacker());
        contentUnpackerRegister.registerContentUnpacker(new PrimitiveBitStringUnpacker());
    }

}
