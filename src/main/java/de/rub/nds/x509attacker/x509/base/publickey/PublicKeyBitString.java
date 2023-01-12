/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base.publickey;

import static de.rub.nds.x509attacker.constants.X509PublicKeyType.DH;
import static de.rub.nds.x509attacker.constants.X509PublicKeyType.DSA;
import static de.rub.nds.x509attacker.constants.X509PublicKeyType.ECDH_ECDSA;
import static de.rub.nds.x509attacker.constants.X509PublicKeyType.ECDH_ONLY;
import static de.rub.nds.x509attacker.constants.X509PublicKeyType.ECMQV;
import static de.rub.nds.x509attacker.constants.X509PublicKeyType.ED25519;
import static de.rub.nds.x509attacker.constants.X509PublicKeyType.ED448;
import static de.rub.nds.x509attacker.constants.X509PublicKeyType.GOST_R3411_2001;
import static de.rub.nds.x509attacker.constants.X509PublicKeyType.GOST_R3411_94;
import static de.rub.nds.x509attacker.constants.X509PublicKeyType.KEA;
import static de.rub.nds.x509attacker.constants.X509PublicKeyType.RSA;
import static de.rub.nds.x509attacker.constants.X509PublicKeyType.RSAES_OAEP;
import static de.rub.nds.x509attacker.constants.X509PublicKeyType.RSASSA_PSS;
import static de.rub.nds.x509attacker.constants.X509PublicKeyType.X25519;
import static de.rub.nds.x509attacker.constants.X509PublicKeyType.X448;

import de.rub.nds.asn1.model.Asn1PrimitiveBitString;
import de.rub.nds.asn1.serializer.Asn1FieldSerializer;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.x509.parser.PublicKeyBitStringParser;
import de.rub.nds.x509attacker.x509.preparator.publickey.PublicKeyBitStringPreparator;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAnyElement;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class PublicKeyBitString extends Asn1PrimitiveBitString<X509Chooser> {

    @XmlAnyElement(lax = true)
    private X509PublicKeyContent x509PublicKeyContent;

    public PublicKeyBitString(String identifier, X509CertificateConfig config) {
        super(identifier);
        this.x509PublicKeyContent = createX509PublicKeyContent(config.getPublicKeyType());
    }

    public PublicKeyBitString(String identifier) {
        super(identifier);
    }

    private PublicKeyBitString() {
        super(null);
    }

    public void setX509PublicKeyContent(X509PublicKeyContent x509PublicKeyContent) {
        this.x509PublicKeyContent = x509PublicKeyContent;
    }

    public X509PublicKeyContent getX509PublicKeyContent() {
        return x509PublicKeyContent;
    }

    @Override
    public PublicKeyBitStringPreparator getPreparator(X509Chooser chooser) {
        return new PublicKeyBitStringPreparator(chooser, this);
    }

    @Override
    public Asn1FieldSerializer getSerializer() {
        return super.getSerializer();
    }

    @Override
    public PublicKeyBitStringParser getParser(X509Chooser chooser) {
        return new PublicKeyBitStringParser(chooser, this);
    }

    public final X509PublicKeyContent createX509PublicKeyContent(X509PublicKeyType publicKeyType) {
        switch (publicKeyType) {
            case DH:
                return new DhPublicKey();
            case DSA:
                return new DsaPublicKey();
            case ECDH_ECDSA:
                return new EcdhEcdsaPublicKey();
            case ECDH_ONLY:
                return new EcdhPublicKey();
            case ECMQV:
                throw new UnsupportedOperationException("ECMQV no supported");
            case ED25519:
                return new Ed25519PublicKey();
            case ED448:
                return new Ed448PublicKey();
            case GOST_R3411_2001:
                throw new UnsupportedOperationException("GOST_R3411_2001 no supported");
            case GOST_R3411_94:
                throw new UnsupportedOperationException("GOST_R3411_94 no supported");
            case KEA:
                throw new UnsupportedOperationException("KEA no supported");
            case RSA:
                return new RsaPublicKey();
            case RSAES_OAEP:
                throw new UnsupportedOperationException("RSAoaep no supported");
            case RSASSA_PSS:
                throw new UnsupportedOperationException("RSASSA_PSS no supported");
            case X25519:
                return new X25519PublicKey();
            case X448:
                return new X448PublicKey();
            default:
                throw new UnsupportedOperationException(
                        "PublicKeyType: "
                                + publicKeyType.getHumanReadableName()
                                + " is not supported.");
        }
    }
}
