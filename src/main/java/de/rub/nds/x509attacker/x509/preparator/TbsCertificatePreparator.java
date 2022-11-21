/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator;

import de.rub.nds.asn1.constants.TimeAccurracy;
import de.rub.nds.asn1.model.Asn1EncapsulatingBitString;
import de.rub.nds.asn1.model.Asn1Field;
import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1PrimitiveGeneralizedTime;
import de.rub.nds.asn1.model.Asn1PrimitiveUtcTime;
import de.rub.nds.asn1.time.TimeEncoder;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.ValidityEncoding;
import de.rub.nds.x509attacker.x509.base.AlgorithmIdentifier;
import de.rub.nds.x509attacker.x509.base.AttributeTypeAndValue;
import de.rub.nds.x509attacker.x509.base.Name;
import de.rub.nds.x509attacker.x509.base.RelativeDistinguishedName;
import de.rub.nds.x509attacker.x509.base.SubjectPublicKeyInfo;
import de.rub.nds.x509attacker.x509.base.TbsCertificate;
import de.rub.nds.x509attacker.x509.base.Time;
import de.rub.nds.x509attacker.x509.base.Validity;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.joda.time.DateTime;

public class TbsCertificatePreparator extends X509ComponentPreparator {

    private static final Logger LOGGER = LogManager.getLogger();

    private final TbsCertificate tbsCertificate;

    public TbsCertificatePreparator(TbsCertificate tbsCertificate, X509CertificateConfig config) {
        super(tbsCertificate, config);
        this.tbsCertificate = tbsCertificate;
    }

    @Override
    public void prepareContent() {
        prepareVersion();
        prepareSerialNumber();
        prepareSignature();
        prepareIssuer();
        prepareValidity();
        prepareSubject();
        prepareSubjectPublicKeyInfo();
        prepareIssuerUniqueId();
        prepareSubjectUniqueId();
        prepareExtensions();
    }

    private void prepareVersion() {

    }

    private void prepareSerialNumber() {
        Asn1Integer serialNumber = tbsCertificate.getSerialNumber();
        serialNumber.setValue(config.getSerialNumber());
        prepareSubcomponent(serialNumber);
    }

    private void prepareSignature() {
        AlgorithmIdentifier signature = tbsCertificate.getSignature();
        Asn1ObjectIdentifier algorithm = signature.getAlgorithm();
        algorithm.setValue(config.getSignatureAlgorithm().getOid().toString());
        prepareSubcomponent(algorithm);
        /**
         * Prepare signature parameters
         */
        signature.instantiateParameters(createSignatureParameters());
        prepareSubcomponent(signature.getParameters());
        prepareSubcomponent(signature);
    }

    private void prepareIssuer() {
        Name issuer = tbsCertificate.getIssuer();
        RelativeDistinguishedName rdn = issuer.getRelativeDistinguishedName();

        List<AttributeTypeAndValue> attributeTypeAndValueList = rdn.getAttributeTypeAndValueList();
        for (AttributeTypeAndValue typeAndValue : attributeTypeAndValueList) {
            typeAndValue.getPreparator().prepare();
        }

    }

    private void prepareValidity() {
        Validity validity = tbsCertificate.getValidity();
        Time notAfter = validity.getNotAfter();
        encodeValidity(config.getNotAfter(), notAfter, config.getDefaultNotAfterEncoding(), config.getNotAfterAccurracy(), config.getTimezoneOffsetInMinutes());
        prepareSubcomponent(notAfter);
        Time notBefore = validity.getNotBefore();
        encodeValidity(config.getNotBefore(), notBefore, config.getDefaultNotBeforeEncoding(), config.getNotBeforeAccurracy(), config.getTimezoneOffsetInMinutes());
        prepareSubcomponent(notBefore);
    }

    private void encodeValidity(DateTime date, Time time, ValidityEncoding encoding, TimeAccurracy accurracy, int timezoneInMinutes) {
        Asn1Field field;
        switch (encoding) {
            case GENERALIZED_TIME_DIFFERENTIAL:
                field = new Asn1PrimitiveGeneralizedTime("generalizedTime");
                ((Asn1PrimitiveGeneralizedTime) field).setValue(TimeEncoder.encodeGeneralizedTimeUtcWithDifferential(date, accurracy, timezoneInMinutes));
                break;
            case GENERALIZED_TIME_LOCAL:
                field = new Asn1PrimitiveGeneralizedTime("generalizedTime");
                ((Asn1PrimitiveGeneralizedTime) field).setValue(TimeEncoder.encodeGeneralizedTimeLocalTime(date, accurracy));
                break;
            case GENERALIZED_TIME_UTC:
                field = new Asn1PrimitiveGeneralizedTime("generalizedTime");
                ((Asn1PrimitiveGeneralizedTime) field).setValue(TimeEncoder.encodeGeneralizedTimeUtc(date, accurracy));
                break;
            case UTC:
                field = new Asn1PrimitiveUtcTime("utcTime");
                ((Asn1PrimitiveUtcTime) field).setValue(TimeEncoder.encodeFullUtc(date, accurracy));
                break;
            case UTC_DIFFERENTIAL:
                field = new Asn1PrimitiveUtcTime("utcTime");
                ((Asn1PrimitiveUtcTime) field).setValue(TimeEncoder.encodeUtcWithDifferential(date, accurracy, timezoneInMinutes));
                break;
            default:
                throw new UnsupportedOperationException("Unsupported validity encoding:" + encoding.name());
        }

    }

    private void prepareSubject() {
        Name subject = tbsCertificate.getSubject();
        RelativeDistinguishedName rdn = subject.getRelativeDistinguishedName();
        List<AttributeTypeAndValue> attributeTypeAndValueList = rdn.getAttributeTypeAndValueList();
        for (AttributeTypeAndValue typeAndValue : attributeTypeAndValueList) {
            typeAndValue.getPreparator().prepare();
        }
    }

    private void prepareSubjectPublicKeyInfo() {
        SubjectPublicKeyInfo subjectPublicKeyInfo = tbsCertificate.getSubjectPublicKeyInfo();
        AlgorithmIdentifier algorithm = subjectPublicKeyInfo.getAlgorithm();
        Asn1EncapsulatingBitString subjectPublicKey = subjectPublicKeyInfo.getSubjectPublicKeyBitString();
        
    }

    private void prepareIssuerUniqueId() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    private void prepareSubjectUniqueId() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    private void prepareExtensions() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    private Asn1Field createSignatureParameters() {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from
        // nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

}
