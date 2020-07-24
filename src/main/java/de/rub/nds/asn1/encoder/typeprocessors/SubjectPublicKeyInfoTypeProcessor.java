package de.rub.nds.asn1.encoder.typeprocessors;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.encoder.encodingoptions.Asn1EncodingOptions;
import de.rub.nds.asn1.encoder.encodingoptions.DefaultX509EncodingOptions;
import de.rub.nds.asn1.model.KeyInfo;
import de.rub.nds.signatureengine.keyparsers.PemUtil;
import de.rub.nds.x509attacker.X509Attributes;
import de.rub.nds.x509attacker.keyfilemanager.KeyFileManager;
import de.rub.nds.x509attacker.keyfilemanager.KeyFileManagerException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.PublicKey;

public class SubjectPublicKeyInfoTypeProcessor extends DefaultX509TypeProcessor {

    private static final Logger LOGGER = LogManager.getLogger();

    private final DefaultX509EncodingOptions encodingOptions;

    private final Asn1Encodable asn1Encodable;

    private byte[] encodedPublicKey = null;

    public SubjectPublicKeyInfoTypeProcessor(final Asn1EncodingOptions encodingOptions, final Asn1Encodable asn1Encodable) {
        super(encodingOptions, asn1Encodable);
        this.encodingOptions = (DefaultX509EncodingOptions) encodingOptions;
        this.asn1Encodable = asn1Encodable;
    }

    @Override
    public void onBeforeChildEncode() {
        if(this.linksAnotherAsn1Encodable()) {
            this.tryCreateSubjectPublicKeyInfoFromLink();
        }
    }

    @Override
    public byte[] encode() {
        byte[] encoded = new byte[0];
        if(this.isFlaggedForEncoding()) {
            if(this.encodedPublicKey != null) {
                encoded = encodedPublicKey;
            }
            else {
                super.encode();
            }
        }
        return encoded;
    }

    private void tryCreateSubjectPublicKeyInfoFromLink() {
        Asn1Encodable linkedAsn1Encodable = this.encodingOptions.linker.getLinkedAsn1Encodable(this.asn1Encodable);
        if(linkedAsn1Encodable instanceof KeyInfo) {
            try {
                KeyInfo keyInfo = (KeyInfo) linkedAsn1Encodable;                
                byte[] keyBytes = keyInfo.getKeyBytes();
                if(keyBytes == null)
                {                    
                    String keyFile = this.resolveKeyFileName(keyInfo);
                    keyBytes = KeyFileManager.getReference().getKeyFileContent(keyFile);
                }
                        
                PublicKey publicKey = this.readPublicKeyFromKeyBytes(keyBytes);
                this.encodedPublicKey = publicKey.getEncoded();
                this.setLinkHandled(true);
            } catch(KeyFileManagerException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private String resolveKeyFileName(KeyInfo keyInfo) {
        String keyFile = keyInfo.getKeyFileName();
        while(keyFile == null || keyFile.isEmpty()) {
            if(keyInfo.hasAttribute(X509Attributes.FROM_IDENTIFIER)) {
                keyInfo = (KeyInfo) this.encodingOptions.linker.getLinkedAsn1Encodable(keyInfo);
                keyFile = keyInfo.getKeyFileName();
            }
            else {
                throw new RuntimeException("KeyInfo must either specify fromIdentifier attribute or a keyFile element containing the file name of a key file!");
            }
        }
        return keyFile;
    }

    private PublicKey readPublicKeyFromKeyBytes(byte[] keyBytes) {
        try {
            return PemUtil.readPublicKey(new ByteArrayInputStream(keyBytes));
        } catch(IOException e) {
            throw new RuntimeException(e);
        }
    }
}
