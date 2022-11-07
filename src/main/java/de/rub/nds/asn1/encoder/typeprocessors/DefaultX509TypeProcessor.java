/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.asn1.encoder.typeprocessors;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.encoder.Asn1Encoder;
import de.rub.nds.asn1.encoder.encodingoptions.Asn1EncodingOptions;
import de.rub.nds.asn1.encoder.encodingoptions.DefaultX509EncodingOptions;
import de.rub.nds.asn1.util.AttributeParser;
import de.rub.nds.x509attacker.X509Attributes;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DefaultX509TypeProcessor extends Asn1TypeProcessor {

    private static final Logger LOGGER = LogManager.getLogger();

    private final DefaultX509EncodingOptions encodingOptions;

    private final Asn1Encodable asn1Encodable;

    private boolean isLinkHandled = false;

    public DefaultX509TypeProcessor(final Asn1EncodingOptions encodingOptions, final Asn1Encodable asn1Encodable) {
        super(encodingOptions, asn1Encodable);
        this.encodingOptions = (DefaultX509EncodingOptions) encodingOptions;
        this.asn1Encodable = asn1Encodable;
    }

    @Override
    public byte[] encode() {
        byte[] encoded = new byte[0];
        if (this.isFlaggedForEncoding()) {
            if (this.linksAnotherAsn1Encodable() && this.isLinkHandled == false) {
                encoded = this.encodeFromLinkedAsn1Encodable();
            } else {
                encoded = this.asn1Encodable.getSerializer().serialize();
            }
        }
        return encoded;
    }

    protected boolean linksAnotherAsn1Encodable() {
        return this.encodingOptions.getLinker().hasLink(this.asn1Encodable);
    }

    private byte[] encodeFromLinkedAsn1Encodable() {
        Asn1Encodable linkedAsn1Encodable = this.encodingOptions.getLinker().getLinkedAsn1Encodable(this.asn1Encodable);
        if (this.asn1Encodable.getType().equals(linkedAsn1Encodable.getType()) == false) {
            LOGGER.warn("Type mismatch: " + this.asn1Encodable.getClass() + " with type " + this.asn1Encodable.getType()
                + " references " + linkedAsn1Encodable.getClass() + " with type " + linkedAsn1Encodable.getType()
                + "! Encoding reference anyways...");
        }
        Asn1Encoder asn1Encoder = new Asn1Encoder(this.encodingOptions, linkedAsn1Encodable);
        return asn1Encoder.encode();
    }

    protected boolean isFlaggedForEncoding() {
        boolean isFlaggedForEncoding = true;
        boolean excludeFromSignature = AttributeParser.parseBooleanAttributeOrDefault(this.asn1Encodable,
            X509Attributes.EXCLUDE_FROM_SIGNATURE, false);
        boolean excludeFromCertificate = AttributeParser.parseBooleanAttributeOrDefault(this.asn1Encodable,
            X509Attributes.EXCLUDE_FROM_CERTIFICATE, false);
        switch (this.encodingOptions.getEncodeTarget()) {
            case FOR_SIGNATURE_ONLY:
                if (excludeFromSignature == true) {
                    isFlaggedForEncoding = false;
                }
                return isFlaggedForEncoding;

            case FOR_CERTIFICATE_ONLY:
                if (excludeFromCertificate == true) {
                    isFlaggedForEncoding = false;
                }
                return isFlaggedForEncoding;
            default:
                return isFlaggedForEncoding;
        }
    }

    protected void setLinkHandled(boolean isLinkHandled) {
        this.isLinkHandled = isLinkHandled;
    }
}
