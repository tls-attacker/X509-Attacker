/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator;

import java.util.Collection;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.joda.time.DateTime;

import de.rub.nds.asn1.constants.TimeAccurracy;
import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1Field;
import de.rub.nds.asn1.model.Asn1GeneralizedTime;
import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1Null;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1UtcTime;
import de.rub.nds.asn1.preparator.Asn1FieldPreparator;
import de.rub.nds.asn1.time.TimeEncoder;
import de.rub.nds.asn1.time.TimeField;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.ValidityEncoding;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import de.rub.nds.x509attacker.x509.base.AlgorithmIdentifier;
import de.rub.nds.x509attacker.x509.base.Name;
import de.rub.nds.x509attacker.x509.base.RelativeDistinguishedName;
import de.rub.nds.x509attacker.x509.base.SubjectPublicKeyInfo;
import de.rub.nds.x509attacker.x509.base.TbsCertificate;
import de.rub.nds.x509attacker.x509.base.Validity;
import de.rub.nds.x509attacker.x509.base.publickey.parameters.PublicParameters;
import de.rub.nds.x509attacker.x509.base.publickey.parameters.X509DhParameters;
import de.rub.nds.x509attacker.x509.base.publickey.parameters.X509DssParameters;
import de.rub.nds.x509attacker.x509.base.publickey.parameters.X509EcNamedCurveParameters;

public class TbsCertificatePreparator extends Asn1FieldPreparator<TbsCertificate>
        implements X509Preparator {

    private static final Logger LOGGER = LogManager.getLogger();

    private final TbsCertificate tbsCertificate;

    private final X509Chooser chooser;

    public TbsCertificatePreparator(X509Chooser chooser, TbsCertificate tbsCertificate) {
        super(tbsCertificate);
        this.chooser = chooser;
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
        tbsCertificate.getVersion().getPreparator(chooser).prepare();
    }

    private void prepareSerialNumber() {
        Asn1Integer serialNumber = tbsCertificate.getSerialNumber();
        serialNumber.setValue(chooser.getConfig().getSerialNumber());
        serialNumber.getPreparator(chooser).prepare();
    }

    private void prepareSignature() {
        AlgorithmIdentifier signature = tbsCertificate.getSignature();
        Asn1ObjectIdentifier algorithm = signature.getAlgorithm();
        algorithm.setValue(chooser.getSignatureAlgorithm().getOid().toString());
        algorithm.getPreparator(chooser).prepare();

        // TODO Updating context, this should probably happen in a handler
        chooser.getContext()
                .setSubjectSignatureAlgorithm(
                        X509SignatureAlgorithm.decodeFromOidBytes(
                                algorithm.getContent().getValue()));

        /** Prepare signature parameters */
        PublicParameters signatureParameters = createSignatureParameters();
        if (signatureParameters == null) {
            signature.instantiateParameters(new Asn1Null("parameters"));
        } else if (signatureParameters instanceof Asn1Field) {
            signature.instantiateParameters((Asn1Field) signatureParameters);
        } else {
            throw new RuntimeException("Signature Parameters are not an ASN.1 Field");
        }
        signature.getParameters().getPreparator(chooser).prepare();
        signature.getPreparator(chooser).prepare();
    }

    private void prepareIssuer() {
        Name issuer = tbsCertificate.getIssuer();
        List<RelativeDistinguishedName> rdnSequence = issuer.getRelativeDistinguishedNames();
        for (RelativeDistinguishedName rdn : rdnSequence) {
            Collection<Asn1Encodable> attributeTypeAndValueList = rdn.getChildren();
            for (Asn1Encodable typeAndValue : attributeTypeAndValueList) {
                typeAndValue.getPreparator(chooser).prepare();
            }
            rdn.getPreparator(chooser).prepare();
        }
        issuer.getPreparator(chooser).prepare();
        issuer.getHandler(chooser).adjustContext();
    }

    private void prepareValidity() {
        Validity validity = tbsCertificate.getValidity();
        TimeField notAfter = validity.getNotAfter();
        encodeValidity(
                chooser.getConfig().getNotAfter(),
                notAfter,
                chooser.getConfig().getDefaultNotAfterEncoding(),
                chooser.getConfig().getNotAfterAccurracy(),
                chooser.getConfig().getTimezoneOffsetInMinutes());
        notAfter.getPreparator(chooser).prepare();
        TimeField notBefore = validity.getNotBefore();
        encodeValidity(
                chooser.getConfig().getNotBefore(),
                notBefore,
                chooser.getConfig().getDefaultNotBeforeEncoding(),
                chooser.getConfig().getNotBeforeAccurracy(),
                chooser.getConfig().getTimezoneOffsetInMinutes());
        notBefore.getPreparator(chooser).prepare();
        validity.getPreparator(chooser).prepare();
    }

    private void encodeValidity(
            DateTime date,
            TimeField time,
            ValidityEncoding encoding,
            TimeAccurracy accurracy,
            int timezoneInMinutes) {
        Asn1Field timeField;
        if (time == null) {
            switch (encoding) {
                case GENERALIZED_TIME_DIFFERENTIAL:
                    timeField = new Asn1GeneralizedTime("generalizedTime");
                    ((Asn1GeneralizedTime) timeField)
                            .setValue(
                                    TimeEncoder.encodeGeneralizedTimeUtcWithDifferential(
                                            date, accurracy, timezoneInMinutes));
                    break;
                case GENERALIZED_TIME_LOCAL:
                    timeField = new Asn1GeneralizedTime("generalizedTime");
                    ((Asn1GeneralizedTime) timeField)
                            .setValue(TimeEncoder.encodeGeneralizedTimeLocalTime(date, accurracy));
                    break;
                case GENERALIZED_TIME_UTC:
                    timeField = new Asn1GeneralizedTime("generalizedTime");
                    ((Asn1GeneralizedTime) timeField)
                            .setValue(TimeEncoder.encodeGeneralizedTimeUtc(date, accurracy));
                    break;
                case UTC:
                    timeField = new Asn1UtcTime("utcTime");
                    ((Asn1UtcTime) timeField).setValue(TimeEncoder.encodeFullUtc(date, accurracy));
                    break;
                case UTC_DIFFERENTIAL:
                    timeField = new Asn1UtcTime("utcTime");
                    ((Asn1UtcTime) timeField)
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
            // There is aready a selection, respect it
            // TODO
        }
    }

    private void prepareSubject() {
        Name subject = tbsCertificate.getSubject();
        List<RelativeDistinguishedName> rdnSequence = subject.getRelativeDistinguishedNames();
        for (RelativeDistinguishedName rdn : rdnSequence) {

            Collection<Asn1Encodable> attributeTypeAndValueList = rdn.getChildren();
            for (Asn1Encodable typeAndValue : attributeTypeAndValueList) {
                typeAndValue.getPreparator(chooser).prepare();
            }
            rdn.getPreparator(chooser).prepare();
        }
        subject.getPreparator(chooser).prepare();
        subject.getHandler(chooser).adjustContext();
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
        algorithm.getAlgorithm().getPreparator(chooser).prepare();
        PublicParameters publicKeyParameters = createPublicKeyParameters();
        if (publicKeyParameters == null) {
            algorithm.instantiateParameters(new Asn1Null("parameters"));
        } else if (publicKeyParameters instanceof Asn1Field) {
            algorithm.instantiateParameters((Asn1Field) publicKeyParameters);
        } else {
            throw new RuntimeException("Signature Parameters are not an ASN.1 Field");
        }
        algorithm.getParameters().getPreparator(chooser).prepare();
        subjectPublicKeyInfo.getSubjectPublicKeyBitString().getPreparator(chooser).prepare();
        subjectPublicKeyInfo.getPreparator(chooser).prepare();
    }

    private void prepareIssuerUniqueId() {
        if (tbsCertificate.getIssuerUniqueID() != null) {
            // IssuerUniqueID is an optional field
            tbsCertificate.getIssuerUniqueID().setUsedBits(chooser.getIssuerUniqueId());
            tbsCertificate.getIssuerUniqueID().getPreparator(chooser).prepare();
        }
    }

    private void prepareSubjectUniqueId() {
        if (tbsCertificate.getSubjectUniqueID() != null) {
            // IssuerUniqueID is an optional field
            tbsCertificate
                    .getSubjectUniqueID()
                    .setUsedBits(chooser.getConfig().getSubjectUniqueId());
            tbsCertificate.getSubjectUniqueID().getPreparator(chooser).prepare();

            // TODO this should probably happen within a handler
            chooser.getContext()
                    .setIssuerUniqueId(
                            tbsCertificate.getSubjectUniqueID().getUsedBits().getValue());
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
                return new X509DhParameters("dhParameters", chooser.getConfig());
            case DSA:
                return new X509DssParameters("dssParameters");
            case ECDH_ECDSA:
                return new X509EcNamedCurveParameters("ecNamedCurve");
            default:
                return null;
        }
    }

    private PublicParameters createPublicKeyParameters() {
        X509PublicKeyType publicKeyType = chooser.getConfig().getPublicKeyType();
        switch (publicKeyType) {
            case DH:
                return new X509DhParameters("dhParameters", chooser.getConfig());
            case DSA:
                return new X509DssParameters("dssParameters");
            case ECDH_ECDSA:
                return new X509EcNamedCurveParameters("ecNamedCurve");
            default:
                return null;
        }
    }
}
