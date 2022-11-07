/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.asn1.encoder.encodingoptions;

import de.rub.nds.asn1.encoder.EncodeTarget;
import de.rub.nds.x509attacker.linker.Linker;

public class DefaultX509EncodingOptions extends DefaultAsn1EncodingOptions {

    private final EncodeTarget encodeTarget;

    private final Linker linker;

    public DefaultX509EncodingOptions(final EncodeTarget encodeTarget, final Linker linker) {
        this.encodeTarget = encodeTarget;
        this.linker = linker;
    }

    public EncodeTarget getEncodeTarget() {
        return encodeTarget;
    }

    public Linker getLinker() {
        return linker;
    }

}
