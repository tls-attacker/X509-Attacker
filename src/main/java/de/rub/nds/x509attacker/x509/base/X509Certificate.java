/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.asn1.model.Asn1PrimitiveBitString;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.serializer.Asn1FieldSerializer;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.context.X509Context;
import de.rub.nds.x509attacker.x509.base.publickey.X509PublicKeyContent;
import de.rub.nds.x509attacker.x509.preparator.X509CertificatePreparator;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509Certificate extends Asn1Sequence<X509Chooser> {

    private static final Logger LOGGER = LogManager.getLogger();

    @HoldsModifiableVariable private TbsCertificate tbsCertificate;

    @HoldsModifiableVariable private AlgorithmIdentifier signatureAlgorithm;

    @HoldsModifiableVariable private Asn1PrimitiveBitString signature;

    public X509Certificate(String identifier, X509CertificateConfig certificateConfig) {
        super(identifier);
        tbsCertificate = new TbsCertificate("tbsCertificate", certificateConfig);
        signatureAlgorithm = new AlgorithmIdentifier("signatureAlgorithm");
        signature = new Asn1PrimitiveBitString("signature");
        addChild(tbsCertificate);
        addChild(signatureAlgorithm);
        addChild(signature);
    }

    public X509Certificate(String identifier) {
        super(identifier);
        tbsCertificate = new TbsCertificate("tbsCertificate");
        signatureAlgorithm = new AlgorithmIdentifier("signatureAlgorithm");
        signature = new Asn1PrimitiveBitString("signature");
        addChild(tbsCertificate);
        addChild(signatureAlgorithm);
        addChild(signature);
    }

    /** Default constructor to please JAXB */
    private X509Certificate() {
        super(null);
    }

    public TbsCertificate getTbsCertificate() {
        return tbsCertificate;
    }

    public void setTbsCertificate(TbsCertificate tbsCertificate) {
        this.tbsCertificate = tbsCertificate;
    }

    public AlgorithmIdentifier getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(AlgorithmIdentifier signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public Asn1PrimitiveBitString getSignature() {
        return signature;
    }

    public void setSignature(Asn1PrimitiveBitString signature) {
        this.signature = signature;
    }

    public void adjustContext(X509Context context, X509CertificateConfig config) {
        X509PublicKeyContent x509PublicKey =
                tbsCertificate
                        .getSubjectPublicKeyInfo()
                        .getSubjectPublicKeyBitString()
                        .getX509PublicKeyContent();
        if (x509PublicKey != null) {
            x509PublicKey.adjustKeyAsIssuer(context, config);
        } else {
            LOGGER.warn("Could not adjust public key for next certificate");
        }
    }

    @Override
    public X509CertificatePreparator getPreparator(X509Chooser chooser) {
        return new X509CertificatePreparator(chooser, this);
    }

    @Override
    public Asn1FieldSerializer getSerializer() {
        return new Asn1FieldSerializer(this);
    }

    public void getParser() {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
