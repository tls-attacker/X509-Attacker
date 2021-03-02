/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.asn1.translator;

import de.rub.nds.asn1.translator.contextcomponents.ParseNativeTypeContextComponent;
import de.rub.nds.asn1.translator.defaultcontextcomponentoptions.*;

public class SubjectPublicKeyInfoContext extends Context {

    public static String NAME = "SubjectPublicKeyInfoContext";

    private static final ContextComponent[] contextComponents = new ContextComponent[] {
        new ContextComponent("algorithm", "AlgorithmIdentifier",
            new ContextComponentOption<?>[] { new Asn1SequenceCCO(AlgorithmIdentifierContext.NAME) }, false, false),
        // TODO: subjectPublicKey Struktur ist abhängig von dem AlgIdentifier, wodurch eine genaue Bennenung der
        // inneeren Struktur erst nach dem Parsten möglich ist
        new ContextComponent("subjectPublicKey", "",
            new ContextComponentOption<?>[] { new Asn1EncapsulatingBitStringCCO(ParseNativeTypesContext.NAME) }, false,
            false) };

    public SubjectPublicKeyInfoContext() {
        super(contextComponents);
    }

    @Override
    public String getName() {
        return NAME;
    }
}
