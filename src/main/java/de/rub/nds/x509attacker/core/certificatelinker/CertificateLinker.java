package de.rub.nds.x509attacker.core.certificatelinker;

import de.rub.nds.x509attacker.asn1.model.Asn1RawField;
import de.rub.nds.x509attacker.x509.meta.LinkingException;
import de.rub.nds.x509attacker.x509.meta.ReferenceHolder;
import de.rub.nds.x509attacker.x509.meta.Referenceable;
import de.rub.nds.x509attacker.x509.model.nonasn1.KeyInfo;
import de.rub.nds.x509attacker.x509.model.nonasn1.RealSignatureInfo;
import de.rub.nds.x509attacker.x509.model.nonasn1.X509CertificateList;
import de.rub.nds.x509attacker.x509.model.types.basiccertificate.X509Certificate;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

public class CertificateLinker {

    private final X509CertificateList certificateList;

    private final HashMap<String, Referenceable> index = new HashMap<>();

    private final List<ReferenceHolder> updatedReferenceHolders = new LinkedList<>();

    public CertificateLinker(final X509CertificateList certificateList) throws CertificateLinkerException {
        this.certificateList = certificateList;
        this.runIndexing();
        this.buildReferences();
    }

    private void runIndexing() throws CertificateLinkerException {
        for (X509Certificate x509Certificate : this.certificateList.getCertificates()) {
            this.crawlToIndex(x509Certificate);
            RealSignatureInfo realSignatureInfo = x509Certificate.getRealSignatureInfo();
            this.addReferenceableToIndex(realSignatureInfo);
        }
    }

    private void crawlToIndex(final Asn1RawField rawField) throws CertificateLinkerException {
        CertificateCrawler certificateCrawler = new CertificateCrawler() {
            @Override
            public void handleField(Asn1RawField field) throws CertificateLinkerException {
                CertificateLinker.this.tryToBuildReference(field);
            }
        };
        certificateCrawler.crawl(rawField);
    }

    private void addReferenceableToIndex(final Referenceable referenceable) throws CertificateLinkerException {
        if (referenceable.getId() != null && !referenceable.getId().isEmpty()) {
            if (this.index.containsKey(referenceable.getId())) {
                throw new CertificateLinkerException("ID " + referenceable.getId() + " already indexed! Make sure that each element with an id != 0 has a unique id!");
            }
            this.index.put(referenceable.getId(), referenceable);
        }
    }

    private void buildReferences() throws CertificateLinkerException {
        for (X509Certificate x509Certificate : this.certificateList.getCertificates()) {
            this.crawlToBuildReferences(x509Certificate);
            RealSignatureInfo realSignatureInfo = x509Certificate.getRealSignatureInfo();
            KeyInfo realSignatureKeyInfo = null;
            if (realSignatureInfo != null) {
                this.buildReference(realSignatureInfo);
                realSignatureKeyInfo = realSignatureInfo.getKeyInfo();
                if (realSignatureKeyInfo != null) {
                    this.buildReference(realSignatureKeyInfo);
                }
            }
        }
    }

    private void buildReference(final ReferenceHolder referenceHolder) throws CertificateLinkerException {
        if (referenceHolder.getFromId() != null && !referenceHolder.getFromId().isEmpty()) {
            Referenceable referenceable = this.index.get(referenceHolder.getFromId());
            if (referenceable == null) {
                throw new CertificateLinkerException("Referenced object with id " + referenceHolder.getFromId() + " is not indexed!");
            }
            try {
                referenceHolder.setReferencedObject(referenceable);
                this.updatedReferenceHolders.add(referenceHolder);
            } catch (LinkingException e) {
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
