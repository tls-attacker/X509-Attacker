/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1BitString;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509Certificate extends Asn1Sequence {
    
    private static final Logger LOGGER = LogManager.getLogger();
    
    @HoldsModifiableVariable
    private TBSCertificate tbsCertificate;
    
    @HoldsModifiableVariable
    private AlgorithmIdentifier signatureAlgorithm;
    
    @HoldsModifiableVariable
    private ASN1BitString signature;
    
    public X509Certificate() {
        super();
        setIdentifier("certificate");
    }
    
    public TBSCertificate getTbsCertificate() {
        return tbsCertificate;
    }
    
    public void setTbsCertificate(TBSCertificate tbsCertificate) {
        this.tbsCertificate = tbsCertificate;
    }
    
    public AlgorithmIdentifier getSignatureAlgorithm() {
        return signatureAlgorithm;
    }
    
    public void setSignatureAlgorithm(AlgorithmIdentifier signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }
    
    public ASN1BitString getSignature() {
        return signature;
    }
    
    public void setSignature(ASN1BitString signature) {
        this.signature = signature;
    }
}
