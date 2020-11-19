/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.asn1.encoder.encodingoptions;

import de.rub.nds.asn1.encoder.EncodeTarget;
import de.rub.nds.x509attacker.linker.Linker;

public class DefaultX509EncodingOptions extends DefaultAsn1EncodingOptions {

    public final EncodeTarget encodeTarget;

    public final Linker linker;

    public DefaultX509EncodingOptions(final EncodeTarget encodeTarget, final Linker linker) {
        this.encodeTarget = encodeTarget;
        this.linker = linker;
    }
}
