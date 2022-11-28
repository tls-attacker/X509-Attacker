/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator;

import de.rub.nds.asn1.constants.TimeAccurracy;
import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1Field;
import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1Null;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1PrimitiveGeneralizedTime;
import de.rub.nds.asn1.model.Asn1PrimitiveUtcTime;
import de.rub.nds.asn1.time.TimeEncoder;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.ValidityEncoding;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import de.rub.nds.x509attacker.x509.base.AlgorithmIdentifier;
import de.rub.nds.x509attacker.x509.base.Name;
import de.rub.nds.x509attacker.x509.base.RelativeDistinguishedName;
import de.rub.nds.x509attacker.x509.base.SubjectPublicKeyInfo;
import de.rub.nds.x509attacker.x509.base.TbsCertificate;
import de.rub.nds.x509attacker.x509.base.Time;
import de.rub.nds.x509attacker.x509.base.Validity;
import de.rub.nds.x509attacker.x509.base.X509Component;
import de.rub.nds.x509attacker.x509.base.publickey.parameters.DhParameters;
import de.rub.nds.x509attacker.x509.base.publickey.parameters.DssParameters;
import de.rub.nds.x509attacker.x509.base.publickey.parameters.EcNamedCurveParameters;
import de.rub.nds.x509attacker.x509.base.publickey.parameters.PublicParameters;
import de.rub.nds.x509attacker.x509.handler.SubjectNameHandler;
import java.util.Collection;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.joda.time.DateTime;

public class TbsCertificatePreparator extends X509ComponentPreparator {

    private static final Logger LOGGER = LogManager.getLogger();

    private final TbsCertificate tbsCertificate;

    public TbsCertificatePreparator(TbsCertificate tbsCertificate, X509Chooser chooser) {
        super(tbsCertificate, chooser);
        this.tbsCertificate = tbsCertificate;
    }

    @Override
    protected byte[] encodeContent() {
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
        tbsCertificate.setEncodedChildren(encodedChildren(tbsCertificate.getChildren()));
        return tbsCertificate.getEncodedChildren().getValue();
    }

    private void prepareVersion() {
        ((Asn1Integer) (tbsCertificate.getVersion().getChild()))
                .setValue(chooser.getConfig().getVersion().getValue());
        prepareSubcomponent(tbsCertificate.getVersion());
    }

    private void prepareSerialNumber() {
        Asn1Integer serialNumber = tbsCertificate.getSerialNumber();
        serialNumber.setValue(chooser.getConfig().getSerialNumber());
        prepareSubcomponent(serialNumber);
    }

    private void prepareSignature() {
        AlgorithmIdentifier signature = tbsCertificate.getSignature();
        Asn1ObjectIdentifier algorithm = signature.getAlgorithm();
        algorithm.setValue(chooser.getSignatureAlgorithm().getOid().toString());
        prepareSubcomponent(algorithm);

        // TODO Updating context, this should probably happen in a handler
        chooser.getContext()
                .setSignatureAlgorithm(
                        X509SignatureAlgorithm.decodeFromOidBytes(
                                algorithm.getContent().getValue()));

        /**
         * Prepare signature parameters
         */
        PublicParameters signatureParameters = createSignatureParameters();
        if (signatureParameters == null) {
            signature.instantiateParameters(new Asn1Null("parameters"));
        } else if (signatureParameters instanceof Asn1Field) {
            signature.instantiateParameters((Asn1Field) signatureParameters);
        } else {
            throw new RuntimeException("Signature Parameters are not an ASN.1 Field");
        }
        prepareSubcomponent(signature.getParameters());
        prepareSubcomponent(signature);
    }

    private void prepareIssuer() {
        Name issuer = tbsCertificate.getIssuer();
        RelativeDistinguishedName rdn = issuer.getRelativeDistinguishedName();

        Collection<Asn1Encodable> attributeTypeAndValueList = rdn.getChildren();
        for (Asn1Encodable typeAndValue : attributeTypeAndValueList) {
            ((X509Component) typeAndValue)
                    .getPreparator(chooser)
                    .prepare(); // TODO unfortunate cast
        }
        prepareSubcomponent(rdn);
        prepareSubcomponent(issuer);
    }

    private void prepareValidity() {
        Validity validity = tbsCertificate.getValidity();
        Time notAfter = validity.getNotAfter();
        encodeValidity(
                chooser.getConfig().getNotAfter(),
                notAfter,
                chooser.getConfig().getDefaultNotAfterEncoding(),
                chooser.getConfig().getNotAfterAccurracy(),
                chooser.getConfig().getTimezoneOffsetInMinutes());
        prepareSubcomponent(notAfter);
        Time notBefore = validity.getNotBefore();
        encodeValidity(
                chooser.getConfig().getNotBefore(),
                notBefore,
                chooser.getConfig().getDefaultNotBeforeEncoding(),
                chooser.getConfig().getNotBeforeAccurracy(),
                chooser.getConfig().getTimezoneOffsetInMinutes());
        prepareSubcomponent(notBefore);
        prepareSubcomponent(validity);
    }

    private void encodeValidity(
            DateTime date,
            Time time,
            ValidityEncoding encoding,
            TimeAccurracy accurracy,
            int timezoneInMinutes) {
        Asn1Field timeField;
        if (time.getSelectedChoice() == null) {
            switch (encoding) {
                case GENERALIZED_TIME_DIFFERENTIAL:
                    timeField = new Asn1PrimitiveGeneralizedTime("generalizedTime");
                    ((Asn1PrimitiveGeneralizedTime) timeField)
                            .setValue(
                                    TimeEncoder.encodeGeneralizedTimeUtcWithDifferential(
                                            date, accurracy, timezoneInMinutes));
                    break;
                case GENERALIZED_TIME_LOCAL:
                    timeField = new Asn1PrimitiveGeneralizedTime("generalizedTime");
                    ((Asn1PrimitiveGeneralizedTime) timeField)
                            .setValue(TimeEncoder.encodeGeneralizedTimeLocalTime(date, accurracy));
                    break;
                case GENERALIZED_TIME_UTC:
                    timeField = new Asn1PrimitiveGeneralizedTime("generalizedTime");
                    ((Asn1PrimitiveGeneralizedTime) timeField)
                            .setValue(TimeEncoder.encodeGeneralizedTimeUtc(date, accurracy));
                    break;
                case UTC:
                    timeField = new Asn1PrimitiveUtcTime("utcTime");
                    ((Asn1PrimitiveUtcTime) timeField)
                            .setValue(TimeEncoder.encodeFullUtc(date, accurracy));
                    break;
                case UTC_DIFFERENTIAL:
                    timeField = new Asn1PrimitiveUtcTime("utcTime");
                    ((Asn1PrimitiveUtcTime) timeField)
                            .setValue(
                                    TimeEncoder.encodeUtcWithDifferential(
                                            date, accurracy, timezoneInMinutes));
                    break;
                default:
                    throw new UnsupportedOperationException(
                            "Unsupported validity encoding:" + encoding.name());
            }
            time.setSelectedChoice(timeField);
        } else {
            //There is aready a selection, respect it
            //TODO 
        }
    }

    private void prepareSubject() {
        Name subject = tbsCertificate.getSubject();
        RelativeDistinguishedName rdn = subject.getRelativeDistinguishedName();
        Collection<Asn1Encodable> attributeTypeAndValueList = rdn.getChildren();
        for (Asn1Encodable typeAndValue : attributeTypeAndValueList) {
            ((X509Component) typeAndValue)
                    .getPreparator(chooser)
                    .prepare(); // TODO unfortunate cast
        }
        prepareSubcomponent(rdn);
        prepareSubcomponent(subject);
        SubjectNameHandler handler = new SubjectNameHandler(rdn, chooser);
        handler.adjustContext();
    }

    private void prepareSubjectPublicKeyInfo() {
        SubjectPublicKeyInfo subjectPublicKeyInfo = tbsCertificate.getSubjectPublicKeyInfo();
        AlgorithmIdentifier algorithm = subjectPublicKeyInfo.getAlgorithm();
        algorithm
                .getAlgorithm()
                .setValue(chooser.getConfig().getPublicKeyType().getOid().toString());
        algorithm
                .getParameters()
                .setIdentifier(chooser.getConfig().getPublicKeyType().getOid().toString());
        prepareSubcomponent(algorithm.getAlgorithm());
        PublicParameters publicKeyParameters = createPublicKeyParameters();
        if (publicKeyParameters == null) {
            algorithm.instantiateParameters(new Asn1Null("parameters"));
        } else if (publicKeyParameters instanceof Asn1Field) {
            algorithm.instantiateParameters((Asn1Field) publicKeyParameters);
        } else {
            throw new RuntimeException("Signature Parameters are not an ASN.1 Field");
        }
        prepareSubcomponent(algorithm.getParameters());
        subjectPublicKeyInfo.getSubjectPublicKeyBitString().getPreparator(chooser).prepare();
        prepareSubcomponent(subjectPublicKeyInfo);
    }

    private void prepareIssuerUniqueId() {
        if (tbsCertificate.getIssuerUniqueID() != null) {
            // IssuerUniqueID is an optional field
            tbsCertificate.getIssuerUniqueID().setValue(chooser.getIssuerUniqueId());
            tbsCertificate.getIssuerUniqueID().setUnusedBits((byte) 0);
            prepareSubcomponent(tbsCertificate.getIssuerUniqueID());
        }
    }

    private void prepareSubjectUniqueId() {
        if (tbsCertificate.getSubjectUniqueID() != null) {
            // IssuerUniqueID is an optional field
            tbsCertificate.getSubjectUniqueID().setValue(chooser.getConfig().getSubjectUniqueId());
            tbsCertificate.getSubjectUniqueID().setUnusedBits((byte) 0);
            prepareSubcomponent(tbsCertificate.getSubjectUniqueID());

            // TODO this should probably happen within a handler
            chooser.getContext()
                    .setIssuerUniqueId(tbsCertificate.getSubjectUniqueID().getValue().getValue());
        }
    }

    private void prepareExtensions() {
        if (tbsCertificate.getExtensionExplicit() != null) {
            LOGGER.warn("Extensions not supported yet");
        }
    }

    private PublicParameters createSignatureParameters() {
        X509PublicKeyType publicKeyType = chooser.getIssuerPublicKeyType();
        switch (publicKeyType) {
            case DH:
                return new DhParameters("dhParameters", chooser.getConfig());
            case DSA:
                return new DssParameters("dssParameters");
            case ECDH_ECDSA:
                return new EcNamedCurveParameters("ecNamedCurve");
            default:
                return null;
        }
    }

    private PublicParameters createPublicKeyParameters() {
        X509PublicKeyType publicKeyType = chooser.getConfig().getPublicKeyType();
        switch (publicKeyType) {
            case DH:
                return new DhParameters("dhParameters", chooser.getConfig());
            case DSA:
                return new DssParameters("dssParameters");
            case ECDH_ECDSA:
                return new EcNamedCurveParameters("ecNamedCurve");
            default:
                return null;
        }
    }
}
