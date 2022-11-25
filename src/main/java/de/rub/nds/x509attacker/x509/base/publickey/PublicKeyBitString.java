/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base.publickey;

import de.rub.nds.asn1.model.Asn1PrimitiveBitString;
import de.rub.nds.asn1.serializer.Asn1FieldSerializer;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.X509Component;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.preparator.X509ComponentPreparator;
import de.rub.nds.x509attacker.x509.preparator.publickey.PublicKeyBitStringPreparator;

public class PublicKeyBitString extends Asn1PrimitiveBitString implements X509Component {

    private X509Component publicKey;

    public PublicKeyBitString(String identifier, X509Component publicKey) {
        super(identifier);
        this.publicKey = publicKey;
    }

    public PublicKeyBitString(String identifier) {
        super(identifier);
    }

    public void setPublicKey(X509Component publicKey) {
        this.publicKey = publicKey;
    }

    public X509Component getPublicKey() {
        return publicKey;
    }

    @Override
    public X509ComponentPreparator getPreparator(X509Chooser chooser) {
        return new PublicKeyBitStringPreparator(this, chooser);
    }

    @Override
    public Asn1FieldSerializer getSerializer() {
        return getGenericSerializer();
    }
}
