/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.asn1.model.Asn1PrimitiveBitString;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509Certificate extends Asn1Sequence {

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
}
