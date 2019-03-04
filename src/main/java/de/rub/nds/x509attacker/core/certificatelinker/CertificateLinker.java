package de.rub.nds.x509attacker.core.certificatelinker;

import de.rub.nds.x509attacker.asn1.model.Asn1RawField;
import de.rub.nds.x509attacker.x509.fieldmeta.ReferenceHolder;
import de.rub.nds.x509attacker.x509.fieldmeta.Referenceable;
import de.rub.nds.x509attacker.x509.model.meta.*;
import de.rub.nds.x509attacker.x509.model.types.basiccertificate.TbsCertificate;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

public class CertificateLinker {

    private final X509CertificateList certificateList;

    private final HashMap<Integer, Referenceable> index = new HashMap<>();

    private final List<ReferenceHolder> updatedReferenceHolders = new LinkedList<>();

    public CertificateLinker(final X509CertificateList certificateList) throws CertificateLinkerException {
        this.certificateList = certificateList;
        this.runIndexing();
        this.buildReferences();
    }

    private void runIndexing() throws CertificateLinkerException {
        for (X509Certificate x509Certificate : this.certificateList.getCertificates()) {
            RealSignatureInfo realSignatureInfo = x509Certificate.getRealSignatureInfo();
            this.addReferenceableToIndex(x509Certificate);
            this.addReferenceableToIndex(realSignatureInfo);
            // So far, only X509Certificate and RealSignatureInfo are referenceable. Hence, no further crawling is required to create the index.
        }
    }

    private void addReferenceableToIndex(Referenceable referenceable) throws CertificateLinkerException {
        if (referenceable.getId() != 0) {
            if (this.index.containsKey(referenceable.getId())) {
                throw new CertificateLinkerException("ID " + referenceable.getId() + " already indexed! Make sure that each element with an id != 0 has a unique id!");
            }
            this.index.put(referenceable.getId(), referenceable);
        }
    }

    private void buildReferences() throws CertificateLinkerException {
        for (X509Certificate x509Certificate : this.certificateList.getCertificates()) {
            TbsCertificate tbsCertificate = x509Certificate.getTbsCertificate();
            Signature signature = x509Certificate.getSignature();
            KeyInfo realSignatureKeyInfo = x509Certificate.getRealSignatureInfo().getKeyInfo();
            this.buildReference(realSignatureKeyInfo);
            this.buildReference(signature);
            this.crawlToBuildReferences(tbsCertificate);
        }
    }

    private void buildReference(final ReferenceHolder referenceHolder) throws CertificateLinkerException {
        if (referenceHolder.getFromId() != 0) {
            Referenceable referenceable = this.index.get(referenceHolder.getFromId());
            if (referenceable == null) {
                throw new CertificateLinkerException("Referenced object with id " + referenceHolder.getFromId() + " is not indexed!");
            }
            try {
                referenceHolder.setReferencedObject(referenceable);
                this.updatedReferenceHolders.add(referenceHolder);
            } catch (ClassCastException e) {
                throw new CertificateLinkerException(e);
            }
        }
    }

    private void crawlToBuildReferences(final Asn1RawField rawField) throws CertificateLinkerException {
        CertificateCrawler certificateCrawler = new CertificateCrawler() {
            @Override
            public void handleField(Asn1RawField field) throws CertificateLinkerException {
                CertificateLinker.this.tryToBuildReference(field);
            }
        };
        certificateCrawler.crawl(rawField);
    }

    private void tryToBuildReference(final Asn1RawField field) throws CertificateLinkerException {
        if (field instanceof ReferenceHolder) {
            this.buildReference((ReferenceHolder) field);
        }
    }

    public void updateReferencedFields() {
        for (ReferenceHolder referenceHolder : this.updatedReferenceHolders) {
            referenceHolder.updateReferencedFields();
        }
    }
}
