/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model.publickey;

import de.rub.nds.asn1.model.Asn1BitString;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.handler.publickey.PublicKeyBitStringHandler;
import de.rub.nds.x509attacker.x509.model.X509Component;
import de.rub.nds.x509attacker.x509.parser.PublicKeyBitStringParser;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.preparator.publickey.PublicKeyBitStringPreparator;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAnyElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class PublicKeyBitString extends Asn1BitString implements X509Component {

    private static final Logger LOGGER = LogManager.getLogger();

    @XmlAnyElement(lax = true)
    private PublicKeyContent x509PublicKeyContent;

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

    public void setX509PublicKeyContent(PublicKeyContent x509PublicKeyContent) {
        this.x509PublicKeyContent = x509PublicKeyContent;
    }

    public PublicKeyContent getX509PublicKeyContent() {
        return x509PublicKeyContent;
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        return new PublicKeyBitStringHandler(chooser, this);
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        return new PublicKeyBitStringParser(chooser, this);
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        return new PublicKeyBitStringPreparator(chooser, this);
    }

    public final PublicKeyContent createX509PublicKeyContent(X509PublicKeyType publicKeyType) {
        LOGGER.debug("Creating X509PublicKeyContent for PublicKeyType: {}", publicKeyType.name());
        switch (publicKeyType) {
            case DH:
                return new X509DhPublicKey();
            case DSA:
                return new X509DsaPublicKey();
            case ECDH_ECDSA:
                return new X509EcdhEcdsaPublicKey();
            case ECDH_ONLY:
                return new X509EcdhPublicKey();
            case ECMQV:
                throw new UnsupportedOperationException("ECMQV not supported");
            case ED25519:
                return new X509Ed25519PublicKey();
            case ED448:
                return new X509Ed448PublicKey();
            case GOST_R3411_2001:
                throw new UnsupportedOperationException("GOST_R3411_2001 not supported");
            case GOST_R3411_94:
                throw new UnsupportedOperationException("GOST_R3411_94 no supported");
            case KEA:
                throw new UnsupportedOperationException("KEA not supported");
            case RSA:
                return new X509RsaPublicKey("rsaPublicKey");
            case RSAES_OAEP:
                throw new UnsupportedOperationException("RSAoaep not supported");
            case RSASSA_PSS:
                return new X509RsaSsaPublicKey(getIdentifier());
            case X25519:
                return new X509X25519PublicKey();
            case X448:
                return new X509X448PublicKey();
            default:
                throw new UnsupportedOperationException(
                        String.format(
                                "PublicKeyType: %s is not supported.",
                                publicKeyType.getHumanReadableName()));
        }
    }
}
