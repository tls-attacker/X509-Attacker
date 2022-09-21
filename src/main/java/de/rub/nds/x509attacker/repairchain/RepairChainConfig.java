/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.repairchain;

import java.util.UUID;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * A Config File which controls the repair of the chain.
 *
 * @author josh
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class RepairChainConfig {

    public enum SignAlgoKeyRelationRepairMode {
        NONE,
        SIGN_ALGO_BASED,
        KEY_BASED
    };

    // Set of repaor config presets
    public static RepairChainConfig createRepairAllAndSignConfig(String keysResourceFolder) {
        RepairChainConfig repairConfig = new RepairChainConfig("", true, true, true, true, true,
            SignAlgoKeyRelationRepairMode.SIGN_ALGO_BASED, true, keysResourceFolder);
        return repairConfig;
    }

    public static RepairChainConfig createRepairOnlyConfig(String keysResourceFolder) {
        RepairChainConfig repairConfig = new RepairChainConfig("", true, true, true, true, true,
            SignAlgoKeyRelationRepairMode.NONE, false, keysResourceFolder);
        return repairConfig;
    }

    public static RepairChainConfig createSignOnlyConfig(String keysResourceFolder) {
        RepairChainConfig repairConfig = new RepairChainConfig("", false, false, false, false, false,
            SignAlgoKeyRelationRepairMode.SIGN_ALGO_BASED, true, keysResourceFolder);
        return repairConfig;
    }

    public static RepairChainConfig createDoNothingConfig(String keysResourceFolder) {
        RepairChainConfig repairConfig = new RepairChainConfig("", false, false, false, false, false,
            SignAlgoKeyRelationRepairMode.NONE, false, keysResourceFolder);
        return repairConfig;
    }

    private UUID repairConfigID;

    private String repairConfigName = "";

    private boolean repairIssuer = true;

    private boolean repairAuthorityKeyIdentifier = true;

    private boolean repairCABit = true;

    private boolean repairPathLen = true;

    private boolean repairKeyUsage = true;

    private SignAlgoKeyRelationRepairMode repairSignAlgoKeyRelation = SignAlgoKeyRelationRepairMode.SIGN_ALGO_BASED;

    private boolean computeChainSignatureAfterRepair = true;

    private String keysResourceFolder = null;

    public RepairChainConfig() {
    }

    public RepairChainConfig(String repairConfigName, boolean repairIssuer, boolean repairAuthorityKeyIdentifier,
        boolean repairCABit, boolean repairPathLen, boolean repairKeyUsage,
        SignAlgoKeyRelationRepairMode repairSignAlgoKeyRelation, boolean computeChainSignatureAfterRepair,
        String keysResourceFolder) {
        this.repairConfigID = UUID.randomUUID();
        this.repairConfigName = repairConfigName;
        this.repairIssuer = repairIssuer;
        this.repairAuthorityKeyIdentifier = repairAuthorityKeyIdentifier;
        this.repairCABit = repairCABit;
        this.repairPathLen = repairPathLen;

        this.repairKeyUsage = repairKeyUsage;
        this.repairSignAlgoKeyRelation = repairSignAlgoKeyRelation;
        this.computeChainSignatureAfterRepair = computeChainSignatureAfterRepair;

        this.keysResourceFolder = keysResourceFolder;

    }

    public boolean isRepairIssuer() {
        return repairIssuer;
    }

    public void setRepairIssuer(boolean repairIssuer) {
        this.repairIssuer = repairIssuer;
    }

    public boolean isRepairAuthorityKeyIdentifier() {
        return repairAuthorityKeyIdentifier;
    }

    public void setRepairAuthorityKeyIdentifier(boolean repairAuthorityKeyIdentifier) {
        this.repairAuthorityKeyIdentifier = repairAuthorityKeyIdentifier;
    }

    public boolean isRepairCABit() {
        return repairCABit;
    }

    public void setRepairCABit(boolean repairCABit) {
        this.repairCABit = repairCABit;
    }

    public boolean isRepairPathLen() {
        return repairPathLen;
    }

    public void setRepairPathLen(boolean repairPathLen) {
        this.repairPathLen = repairPathLen;
    }

    public boolean isRepairKeyUsage() {
        return repairKeyUsage;
    }

    public void setRepairKeyUsage(boolean repairKeyUsage) {
        this.repairKeyUsage = repairKeyUsage;
    }

    public SignAlgoKeyRelationRepairMode getRepairSignAlgoKeyRelation() {
        return repairSignAlgoKeyRelation;
    }

    public void setRepairSignAlgoKeyRelation(SignAlgoKeyRelationRepairMode repairSignAlgoKeyRelation) {
        this.repairSignAlgoKeyRelation = repairSignAlgoKeyRelation;
    }

    public boolean isComputeChainSignatureAfterRepair() {
        return computeChainSignatureAfterRepair;
    }

    public void setComputeChainSignatureAfterRepair(boolean computeChainSignatureAfterRepair) {
        this.computeChainSignatureAfterRepair = computeChainSignatureAfterRepair;
    }

    public String getKeysResourceFolder() {
        return keysResourceFolder;
    }

    public void setKeysResourceFolder(String keysResourceFolder) {
        this.keysResourceFolder = keysResourceFolder;
    }

    public UUID getReapirConfigID() {
        return repairConfigID;
    }

    public void setReapirConfigID(UUID reapirConfigID) {
        this.repairConfigID = reapirConfigID;
    }

    public String getRepairConfigName() {
        return repairConfigName;
    }

    public void setRepairConfigName(String repairConfigName) {
        this.repairConfigName = repairConfigName;
    }

    @Override
    public String toString() {
        return "RepairChainConfig{" + "repairIssuer=" + repairIssuer + ", repairAuthorityKeyIdentifier="
            + repairAuthorityKeyIdentifier + ", repairCABit=" + repairCABit + ", repairPathLen=" + repairPathLen
            + ", repairKeyUsage=" + repairKeyUsage + ", repairSignAlgoKeyRelation=" + repairSignAlgoKeyRelation
            + ", computeChainSignatureAfterRepair=" + computeChainSignatureAfterRepair + '}';
    }

}
