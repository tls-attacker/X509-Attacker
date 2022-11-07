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
import de.rub.nds.asn1.model.Asn1PseudoType;
import de.rub.nds.asn1.model.SignatureInfo;
import de.rub.nds.asn1.parser.Asn1Parser;
import de.rub.nds.asn1.parser.ParserException;
import de.rub.nds.asn1.parser.contentunpackers.ContentUnpackerRegister;
import de.rub.nds.asn1.parser.contentunpackers.DefaultContentUnpacker;
import de.rub.nds.asn1.parser.contentunpackers.PrimitiveBitStringUnpacker;
import de.rub.nds.asn1.translator.*;
import de.rub.nds.asn1tool.Asn1Tool;
import de.rub.nds.asn1tool.xmlparser.JaxbClassList;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.x509attacker.registry.Registry;
import java.util.List;
import org.junit.jupiter.api.Test;

public class Asn1ParserTest {

    @Test
    public void testAsn1Parser() throws ParserException {
        System.out.println("Test Asn1 Parser");

        try {
            Registry.getInstance();

            // Test von ExtensionContent only/ Unterscheiden zwischen Boolean und octedString
            byte[] extensionContent =
                ArrayConverter.hexStringToByteArray("0603551D23041830168014BBAF7E023DFAA6F13C848EADEE3898ECD93232D4");
            Asn1Parser asn1Parser2 = new Asn1Parser(extensionContent, false);
            List<Asn1Encodable> asn1Encodables2 = asn1Parser2.parse(ExtensionContext.NAME);

            System.out.println("Done.");
        } catch (ParserException e) {
            throw new ParserException(e);
        }

    }

    private static void registerXmlClasses() {
        JaxbClassList jaxbClassList = JaxbClassList.getInstance();
        jaxbClassList.addClasses(Asn1Tool.getAsn1ToolJaxbClasses());
        jaxbClassList.addClasses(Asn1PseudoType.class, SignatureInfo.class);
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
