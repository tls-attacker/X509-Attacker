/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.repairchain;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1Boolean;
import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1PrimitiveBitString;
import de.rub.nds.asn1.model.Asn1PrimitiveOctetString;
import de.rub.nds.x509attacker.exceptions.RepairChainException;
import de.rub.nds.x509attacker.exceptions.X509ModificationException;
import de.rub.nds.x509attacker.x509.X509Certificate;
import de.rub.nds.x509attacker.x509.X509CertificateChain;
import java.math.BigInteger;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Helper class to repair a X509certificate chain regarding different repair configurations
 */
public class RepairChain {

    private static final Logger LOGGER = LogManager.getLogger();

    public static RepairChainStatus repair(RepairChainConfig repairConfig, X509CertificateChain chain) {
        LOGGER.trace("Repairing chain started (" + repairConfig.toString() + ")");
        boolean error = false;
        StringBuilder statusMessage = new StringBuilder();

        if (repairConfig.isRepairIssuer()) {
            try {
                repairIssuer(chain);
                statusMessage.append("repair Issuer: success").append("\n");
            } catch (RepairChainException e) {
                error = true;
                statusMessage.append("repair Issuer: failed => \n").append(e).append("\n");
            }
        }

        if (repairConfig.isRepairAuthorityKeyIdentifier()) {
            try {
                repairAuthorityKeyIdentifier(chain);
                statusMessage.append("repair AuthorityKeyIdentifier: success").append("\n");
            } catch (RepairChainException e) {
                error = true;
                statusMessage.append("repair AuthorityKeyIdentifier: failed => \n").append(e).append("\n");
            }
        }

        if (repairConfig.isRepairCABit()) {
            try {
                repairCABit(chain);
                statusMessage.append("repair CABit: success").append("\n");
            } catch (RepairChainException e) {
                error = true;
                statusMessage.append("repair CABit: failed => \n").append(e).append("\n");
            }
        }

        if (repairConfig.isRepairPathLen()) {
            try {
                repairPathLen(chain);
                statusMessage.append("repair PathLen: success").append("\n");
            } catch (RepairChainException e) {
                error = true;
                statusMessage.append("repair PathLen: failed => \n").append(e).append("\n");
            }

        }

        if (repairConfig.isRepairKeyUsage()) {
            try {
                repairKeyUsage(chain);
                statusMessage.append("repair KeyUsage: success").append("\n");
            } catch (RepairChainException e) {
                error = true;
                statusMessage.append("repair RepairKeyUsage: failed => \n").append(e).append("\n");
            }
        }

        if (repairConfig.isComputeChainSignatureAfterRepair()) {
            try {
                chain.signAllCertificates();
                statusMessage.append("compute ChainSignature after repair: success").append("\n");
            } catch (Exception e) {
                error = true;
                statusMessage.append("compute ChainSignature after repair: failed => \n").append(e).append("\n");
            }

        }

        // TODO: Check if builder is empty an set status to RepairNotihing: success
        if (statusMessage.length() == 0) {
            statusMessage.append("repair do nothing: success").append("\n");
        }

        RepairChainStatus repairChainStatus = new RepairChainStatus(!error, statusMessage.toString());
        LOGGER.trace("repair chain finished (" + repairChainStatus.toString() + ")");
        return repairChainStatus;
    }

    private static void repairIssuer(X509CertificateChain chain) throws RepairChainException {
        List<X509Certificate> certificateChain = chain.getCertificateChain();
        boolean error = false;
        StringBuilder errorMessage = new StringBuilder();

        if (certificateChain.size() >= 1) {
            // --- repair of root ---
            try {
                // set root.issuer Field = root.subject
                certificateChain.get(0).getIdentifierMap().setElementByIDPath("/certificate/tbsCertificate/issuer",
                    certificateChain.get(0).getIdentifierMap().getCopyByIDPath("/certificate/tbsCertificate/subject"));

            } catch (X509ModificationException e) {
                error = true;
                errorMessage.append("failed to repair Issuer for certificate 0: ").append(e).append('\n');
            }

            // --- intermediate / leaf certificates ---
            for (int i = 1; i <= certificateChain.size() - 1; i++) {
                try {
                    // set cert(i).issuer Field = cert(i-1).subject
                    certificateChain.get(i).getIdentifierMap().setElementByIDPath("/certificate/tbsCertificate/issuer",
                        certificateChain.get(i - 1).getIdentifierMap()
                            .getCopyByIDPath("/certificate/tbsCertificate/subject"));
                } catch (X509ModificationException e) {
                    error = true;
                    errorMessage.append("failed to repair Issuer for certificate " + i + ":").append(e).append('\n');
                }

            }
        }

        if (error == true) {
            throw new RepairChainException(errorMessage.toString());
        }

    }

    private static void repairAuthorityKeyIdentifier(X509CertificateChain chain) throws RepairChainException {
        List<X509Certificate> certificateChain = chain.getCertificateChain();

        boolean error = false;
        StringBuilder errorMessage = new StringBuilder();

        if (certificateChain.size() >= 1) {
            // --- repair of root ---
            try {
                // set root.AuthorityKeyIdentifier = root.SubjectKeyIdentifier
                List<String> pathsAKI =
                    certificateChain.get(0).getIdentifierMap().getIDPathsByType("AuthorityKeyIdentifier");
                List<String> pathsSKI =
                    certificateChain.get(0).getIdentifierMap().getIDPathsByType("SubjectKeyIdentifier");

                if (pathsAKI == null) {
                    throw new NullPointerException("AuthorityKeyIdentifier is null");
                }
                if (pathsSKI == null) {
                    throw new NullPointerException("SubjectKeyIdentifier is null");
                }

                if (!pathsAKI.isEmpty() && !pathsSKI.isEmpty()) {
                    byte[] content = ((Asn1PrimitiveOctetString) certificateChain.get(0).getIdentifierMap()
                        .getElementByIDPath(pathsSKI.get(0))).getValue();

                    ((Asn1PrimitiveOctetString) certificateChain.get(0).getIdentifierMap()
                        .getElementByIDPath(pathsAKI.get(0) + "/keyIdentifier")).setValue(content);
                }

            } catch (NullPointerException e) {
                error = true;
                errorMessage.append("failed to repair AKI for certificate 0: ").append(e).append('\n');
            }

            // --- repair of intermediate / leaf certificates ---
            for (int i = 1; i <= certificateChain.size() - 1; i++) {
                try {
                    // set cert(i).AuthorityKeyIdentifier = cert(i-1).SubjectKeyIdentifier from ParentCertificate
                    List<String> pathsAKI =
                        certificateChain.get(i).getIdentifierMap().getIDPathsByType("AuthorityKeyIdentifier");
                    List<String> pathsSKI =
                        certificateChain.get(i - 1).getIdentifierMap().getIDPathsByType("SubjectKeyIdentifier");

                    if (pathsAKI == null) {
                        throw new NullPointerException("AuthorityKeyIdentifier is null");
                    }
                    if (pathsSKI == null) {
                        throw new NullPointerException("SubjectKeyIdentifier is null");
                    }

                    if (!pathsAKI.isEmpty() && !pathsSKI.isEmpty()) {
                        byte[] content = ((Asn1PrimitiveOctetString) certificateChain.get(i - 1).getIdentifierMap()
                            .getElementByIDPath(pathsSKI.get(0))).getValue();

                        ((Asn1PrimitiveOctetString) certificateChain.get(i).getIdentifierMap()
                            .getElementByIDPath(pathsAKI.get(0) + "/keyIdentifier")).setValue(content);
                    }

                } catch (NullPointerException e) {
                    error = true;
                    errorMessage.append("failed to repair AKI for certificate ").append(i).append(":").append(e)
                        .append('\n');
                }

            }
        }

        if (error == true) {
            throw new RepairChainException(errorMessage.toString());
        }
    }

    private static void repairCABit(X509CertificateChain chain) throws RepairChainException {
        List<X509Certificate> certificateChain = chain.getCertificateChain();
        boolean error = false;
        StringBuilder errorMessage = new StringBuilder();

        if (certificateChain.size() >= 1) {
            // --- repair of root ---
            try {
                // set root.CABit
                List<String> pathsBasicConstraints =
                    certificateChain.get(0).getIdentifierMap().getIDPathsByType("BasicConstraints");
                if (pathsBasicConstraints == null) {
                    throw new NullPointerException("BasicConstraints is null");
                }
                if (!pathsBasicConstraints.isEmpty()) {
                    Asn1Boolean asn1Ca = (Asn1Boolean) certificateChain.get(0).getIdentifierMap()
                        .getElementByIDPath(pathsBasicConstraints.get(0) + "/ca");
                    if (asn1Ca != null) {
                        asn1Ca.setValue(true);
                    } else {
                        Asn1Boolean newAsn1CA = new Asn1Boolean();
                        newAsn1CA.setValue(true);
                        newAsn1CA.setIdentifier("ca");
                        certificateChain.get(0).getIdentifierMap()
                            .setElementByIDPath(pathsBasicConstraints.get(0) + "/ca", newAsn1CA);

                    }
                }
            } catch (NullPointerException | X509ModificationException e) {
                error = true;
                errorMessage.append("failed to repair CABit for certificate 0:").append(e).append('\n');
            }

            // --- repair of intermediate / leaf certificates ---
            for (int i = 1; i <= certificateChain.size() - 1; i++) {
                // (only for inter-Certs)
                if (i != certificateChain.size()) {
                    try {
                        // set cert(i).setCABit
                        List<String> pathsBasicConstraints =
                            certificateChain.get(i).getIdentifierMap().getIDPathsByType("BasicConstraints");
                        if (pathsBasicConstraints == null) {
                            throw new NullPointerException("cert does not contain a BasicConstraints (is null)");
                        }

                        if (!pathsBasicConstraints.isEmpty()) {
                            Asn1Boolean asn1Ca = (Asn1Boolean) certificateChain.get(i).getIdentifierMap()
                                .getElementByIDPath(pathsBasicConstraints.get(0) + "/ca");
                            if (asn1Ca != null) {
                                asn1Ca.setValue(true);
                            } else {
                                Asn1Boolean newAsn1CA = new Asn1Boolean();
                                newAsn1CA.setValue(true);
                                newAsn1CA.setIdentifier("ca");
                                certificateChain.get(i).getIdentifierMap()
                                    .setElementByIDPath(pathsBasicConstraints.get(0) + "/ca", newAsn1CA);

                            }

                        }
                    } catch (NullPointerException | X509ModificationException e) {
                        error = true;
                        errorMessage.append("failed to repair CABit for certificate " + i + ":").append(e).append('\n');
                    }
                }
            }
        }

        if (error == true) {
            throw new RepairChainException(errorMessage.toString());
        }
    }

    // TODO: not sure if the pathLen Attribute must be set or if it is optional (indepentent from the ca bit)
    // https://tools.ietf.org/html/rfc5280#section-4.2.1.9
    // currently: it does not create a pathlen asn1 element if its missing
    private static void repairPathLen(X509CertificateChain chain) throws RepairChainException {
        List<X509Certificate> certificateChain = chain.getCertificateChain();

        boolean error = false;
        StringBuilder errorMessage = new StringBuilder();

        if (certificateChain.size() >= 1) {
            // --- repair of root ---
            try {
                // set root.Pathlen
                List<String> pathsBasicConstraints =
                    certificateChain.get(0).getIdentifierMap().getIDPathsByType("BasicConstraints");
                if (pathsBasicConstraints == null) {
                    throw new NullPointerException("cert does not contain a BasicConstraints (is null)");
                }
                if (!pathsBasicConstraints.isEmpty()) {
                    // CA Certificate does not have a pathlen
                    Asn1Integer asn1PathLen = (Asn1Integer) certificateChain.get(0).getIdentifierMap()
                        .getElementByIDPath(pathsBasicConstraints.get(0) + "/pathLenConstraint");
                    if (asn1PathLen != null) {
                        asn1PathLen.setValue(BigInteger.valueOf(certificateChain.size() - 1));
                    } else {
                        // TODO: do not throw Error; it seems like that fixing the path len is only necessary if it is
                        // available
                        // throw new NullPointerException("cert does not contain a PathLenConstraint (is null)");
                    }

                }

            } catch (NullPointerException e) {
                error = true;
                errorMessage.append("failed to repair PathLen for certificate 0:").append(e).append('\n');
            }

            // --- repair of intermediate / leaf certificates ---
            for (int i = 1; i <= certificateChain.size() - 1; i++) {
                // (only for inter-Certs)
                if (i != certificateChain.size()) {
                    try {
                        // set cert(i).Pathlen
                        List<String> pathsBasicConstraints =
                            certificateChain.get(i).getIdentifierMap().getIDPathsByType("BasicConstraints");
                        if (pathsBasicConstraints == null) {
                            throw new NullPointerException("cert does not contain a BasicConstraints (is null)");
                        }
                        if (!pathsBasicConstraints.isEmpty()) {
                            // Intermediate Pathlen = number of maximum allowed follwoing intermediate certificates
                            Asn1Integer asn1PathLen = (Asn1Integer) certificateChain.get(i).getIdentifierMap()
                                .getElementByIDPath(pathsBasicConstraints.get(0) + "/pathLenConstraint");
                            if (asn1PathLen != null) {
                                asn1PathLen.setValue(BigInteger.valueOf(certificateChain.size() - 1 - i));
                            } else {
                                // TODO: do not throw Error; it seems like that fixing the path len is only necessary if
                                // it is available
                                // throw new NullPointerException("cert does not contain a PathLenConstraint (is
                                // null)");
                            }
                        }
                    } catch (NullPointerException e) {
                        error = true;
                        errorMessage.append("failed to repair PathLen for certificate " + i + ":").append(e)
                            .append('\n');
                    }
                }
            }
        }

        if (error == true) {
            throw new RepairChainException(errorMessage.toString());
        }

    }

    private static void repairKeyUsage(X509CertificateChain chain) throws RepairChainException {
        List<X509Certificate> certificateChain = chain.getCertificateChain();

        boolean error = false;
        StringBuilder errorMessage = new StringBuilder();

        if (certificateChain.size() >= 1) {
            // --- repair of root ---

            // set root.KeyUsageBit CertificateSign
            List<Asn1Encodable> keyUsageAsn1 = certificateChain.get(0).getIdentifierMap().getElementsByType("KeyUsage");

            if (keyUsageAsn1 != null && !keyUsageAsn1.isEmpty()
                && keyUsageAsn1.get(0) instanceof Asn1PrimitiveBitString) {
                byte[] value = ((Asn1PrimitiveBitString) keyUsageAsn1.get(0)).getValue();
                value[0] = (byte) (value[0] | (1 << 2));
                ((Asn1PrimitiveBitString) keyUsageAsn1.get(0)).setValue(value);
                ((Asn1PrimitiveBitString) keyUsageAsn1.get(0)).setUnusedBits(2);
            } else {
                error = true;
                errorMessage
                    .append(
                        "failed to repair KeyUsage for certificate 0: keyUsage is null or not Asn1PrimitiveBitString")
                    .append('\n');
            }

            // --- repair of intermediate / leaf certificates ---
            for (int i = 1; i <= certificateChain.size() - 1; i++) {
                // (only for inter-Certs)
                if (i != certificateChain.size()) {

                    // set cert(i).KeyUsageBit CertificateSign
                    keyUsageAsn1 = certificateChain.get(i).getIdentifierMap().getElementsByType("KeyUsage");

                    if (keyUsageAsn1 != null && !keyUsageAsn1.isEmpty()
                        && keyUsageAsn1.get(0) instanceof Asn1PrimitiveBitString) {
                        byte[] value = ((Asn1PrimitiveBitString) keyUsageAsn1.get(0)).getValue();
                        value[0] = (byte) (value[0] | (1 << 2));
                        ((Asn1PrimitiveBitString) keyUsageAsn1.get(0)).setValue(value);
                        ((Asn1PrimitiveBitString) keyUsageAsn1.get(0)).setUnusedBits(2);
                    } else {
                        error = true;
                        errorMessage.append("failed to repair KeyUsage for certificate ").append(i)
                            .append(": keyUsage is null or not Asn1PrimitiveBitString").append('\n');
                    }

                }
            }
        }

        if (error == true) {
            throw new RepairChainException(errorMessage.toString());
        }

    }
}
