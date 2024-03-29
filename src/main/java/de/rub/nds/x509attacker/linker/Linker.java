/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.linker;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.util.AttributeParser;
import de.rub.nds.x509attacker.X509Attributes;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class Linker {

    private final Map<String, Asn1Encodable> identifierMap;

    private Map<Asn1Encodable, Asn1Encodable> links = new HashMap<>();

    public Linker(final Map<String, Asn1Encodable> identifierMap) {
        this.identifierMap = identifierMap;
        this.runLinking();
    }

    public void runLinking() {
        List<Asn1Encodable> asn1Encodables = new LinkedList<>(this.identifierMap.values());
        for (Asn1Encodable asn1Encodable : asn1Encodables) {
            if (asn1Encodable.hasAttribute(X509Attributes.FROM_IDENTIFIER)) {
                String fromIdentifier =
                    AttributeParser.parseStringAttribute(asn1Encodable, X509Attributes.FROM_IDENTIFIER);
                this.resolveAndBuildLink(asn1Encodable, fromIdentifier);
            }
        }
    }

    private void resolveAndBuildLink(final Asn1Encodable asn1Encodable, final String fromIdentifier) {
        if (fromIdentifier.isEmpty() == false) {
            if (this.identifierMap.containsKey(fromIdentifier)) {
                Asn1Encodable referencedAsn1Encodable = this.identifierMap.get(fromIdentifier);
                this.buildLink(asn1Encodable, referencedAsn1Encodable);
            } else {
                throw new LinkerException(
                    "Cannot build link from " + asn1Encodable + " for fromIdentifier " + fromIdentifier + "!");
            }
        }
    }

    private void buildLink(final Asn1Encodable asn1Encodable, final Asn1Encodable referencedAsn1Encodable) {
        this.links.put(asn1Encodable, referencedAsn1Encodable);
    }

    public boolean hasLink(final Asn1Encodable asn1Encodable) {
        return this.links.containsKey(asn1Encodable);
    }

    public Asn1Encodable getLinkedAsn1Encodable(final Asn1Encodable asn1Encodable) {
        return this.links.get(asn1Encodable);
    }
}
