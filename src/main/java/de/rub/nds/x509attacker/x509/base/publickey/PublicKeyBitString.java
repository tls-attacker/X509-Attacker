/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base.publickey;

import de.rub.nds.asn1.model.Asn1PrimitiveBitString;
import de.rub.nds.asn1.serializer.Asn1FieldSerializer;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.context.X509Context;
import de.rub.nds.x509attacker.x509.base.X509Component;
import de.rub.nds.x509attacker.x509.preparator.X509ComponentPreparator;
import de.rub.nds.x509attacker.x509.preparator.publickey.PublicKeyBitStringPreparator;
import jakarta.xml.bind.annotation.XmlAnyElement;

public class PublicKeyBitString extends Asn1PrimitiveBitString
        implements X509Component, X509PublicKey {

    @XmlAnyElement(lax = true)
    private X509Component publicKey;

    @XmlAnyElement(lax = true)
    private X509PublicKey x509PublicKey;

    public PublicKeyBitString(String identifier, X509Component publicKey) {
        super(identifier);
        this.publicKey = publicKey;
        if (publicKey instanceof X509PublicKey) {
            x509PublicKey = (X509PublicKey) publicKey;
        }
    }

    public PublicKeyBitString(String identifier) {
        super(identifier);
    }

    public void setPublicKey(X509Component publicKey) {
        this.publicKey = publicKey;
        if (publicKey instanceof X509PublicKey) {
            x509PublicKey = (X509PublicKey) publicKey;
        }
    }

    public X509PublicKey getX509PublicKey() {
        return x509PublicKey;
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

    @Override
    public void adjustKeyAsIssuer(X509Context context, X509CertificateConfig config) {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from
        // nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public boolean isEllipticCurve() {
        return x509PublicKey.isEllipticCurve();
    }
}
