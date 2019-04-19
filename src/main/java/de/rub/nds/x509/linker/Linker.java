package de.rub.nds.x509.linker;

import de.rub.nds.asn1.model.*;
import de.rub.nds.x509.model.*;
import de.rub.nds.x509.model.rfc5280.AlgorithmIdentifier;
import de.rub.nds.x509.model.rfc5280.X509Certificate;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class Linker {

    private final Object baseObject;

    private final List<Linkeable> allLinkeables = new LinkedList<>();

    private final Map<String, Linkeable> identifiedLinkeables = new HashMap<>();

    /**
     * Creates an instance of Linker. Also calls runIndexing and runLinking when being constructed.
     *
     * @param baseObject The object to start crawling for Linkeables.
     * @throws LinkerException
     */
    public Linker(Object baseObject) throws LinkerException {
        this.baseObject = baseObject;
        this.runIndexing();
        this.runLinking();
    }

    /**
     * Triggers the indexing of all Linkeables that can be found in a search starting from the base object.
     */
    public void runIndexing() throws LinkerException {
        this.identifiedLinkeables.clear();
        this.runIndexing(this.baseObject);
    }

    private void runIndexing(Object object) throws LinkerException {
        if (object != null) {
            if (object instanceof Linkeable) {
                this.addLinkeable((Linkeable) object);
            }

            // Run indexing for children of container classes
            if (object instanceof X509CertificateList) {
                this.runIndexingForX509CertificateList((X509CertificateList) object);
            }
            if (object instanceof X509Certificate) {
                this.runIndexingForX509Certificate((X509Certificate) object);
            }
            if (object instanceof RealSignatureInfo) {
                this.runIndexingForRealSignatureInfo((RealSignatureInfo) object);
            }
            if (object instanceof X509FieldContainer) {
                this.runIndexingForX509FieldContainer((X509FieldContainer) object);
            }
            if (object instanceof X509Field) {
                this.runIndexingForX509Field((X509Field) object);
            }
            if (object instanceof Asn1FieldContainer) {
                this.runIndexingForAsn1FieldContainer((Asn1FieldContainer) object);
            }
            if (object instanceof Asn1Implicit) {
                this.runIndexingForAsn1Implicit((Asn1Implicit) object);
            }
            if (object instanceof Asn1Choice) {
                this.runIndexingForAsn1Choice((Asn1Choice) object);
            }
        }
    }

    private void runIndexingForX509CertificateList(X509CertificateList x509CertificateList) throws LinkerException {
        List<X509Certificate> certificates = x509CertificateList.getCertificates();
        for (X509Certificate certificate : certificates) {
            this.runIndexing(certificate);
        }
    }

    private void runIndexingForX509Certificate(X509Certificate x509Certificate) throws LinkerException {
        List<RealSignatureInfo> realSignatureInfos = x509Certificate.getRealSignatureInfos();
        for (RealSignatureInfo realSignatureInfo : realSignatureInfos) {
            this.runIndexing(realSignatureInfo);
        }
    }

    private void runIndexingForRealSignatureInfo(RealSignatureInfo realSignatureInfo) throws LinkerException {
        AlgorithmIdentifier algorithmIdentifier = realSignatureInfo.getAlgorithmIdentifier();
        KeyInfo keyInfo = realSignatureInfo.getKeyInfo();
        if (algorithmIdentifier != null) {
            this.runIndexing(algorithmIdentifier);
        }
        if (keyInfo != null) {
            this.runIndexing(keyInfo);
        }
    }

    private void runIndexingForX509FieldContainer(X509FieldContainer x509FieldContainer) throws LinkerException {
        List<Asn1Encodable> asn1Encodables = x509FieldContainer.getFields();
        for (Asn1Encodable asn1Encodable : asn1Encodables) {
            this.runIndexing(asn1Encodable);
        }
    }

    private void runIndexingForX509Field(X509Field x509Field) throws LinkerException {
        Asn1Field asn1Field = x509Field.getAsn1Type();
        this.runIndexing(asn1Field);
    }

    private void runIndexingForAsn1FieldContainer(Asn1FieldContainer asn1FieldContainer) throws LinkerException {
        List<Asn1Encodable> asn1Encodables = asn1FieldContainer.getChildren();
        for (Asn1Encodable asn1Encodable : asn1Encodables) {
            this.runIndexing(asn1Encodable);
        }
    }

    private void runIndexingForAsn1Implicit(Asn1Implicit asn1Implicit) throws LinkerException {
        Asn1Encodable asn1Encodable = asn1Implicit.getAsn1Encodable();
        this.runIndexing(asn1Encodable);
    }

    private void runIndexingForAsn1Choice(Asn1Choice asn1Choice) throws LinkerException {
        Asn1Encodable asn1Encodable = asn1Choice.getChosenAsn1Encodable();
        this.runIndexing(asn1Encodable);
    }

    private void addLinkeable(Linkeable linkeable) throws LinkerException {
        String id = linkeable.getId();
        this.allLinkeables.add(linkeable);
        if (id != null && !id.isEmpty()) {
            if (this.identifiedLinkeables.containsKey(id)) {
                throw new LinkerException("ID " + id + " is assigned more than once. This is not permitted!");
            } else {
                this.identifiedLinkeables.put(id, linkeable);
            }
        }
    }

    /**
     * Runs the linking process, i.e. it resolves the Linkeables' IDs and calls the corresponding
     * updateWithReferencedObject method.
     */
    public void runLinking() throws LinkerException {
        for (Linkeable linkeable : this.allLinkeables) {
            String fromId = linkeable.getFromId();
            if (this.identifiedLinkeables.containsKey(fromId)) {
                linkeable.updateWithReferencedObject(this.identifiedLinkeables.get(fromId));
            }
        }
    }
}
