package de.rub.nds.x509attacker.repairchain;

import javax.xml.bind.annotation.XmlRootElement;

/**
 * A Config File which controls the repair of the chain.
 * 
 * @author josh
 */
@XmlRootElement
public class RepairChainConfig {
    
    public enum SignAlgoKeyRelationRepairMode {NONE, SIGN_ALGO_BASED, KEY_BASED};
    
    public static RepairChainConfig createRepairAllAndSignConfig() {
        return new RepairChainConfig();
    }
    
    public static RepairChainConfig createRepairOnlyConfig() {
        return new RepairChainConfig(true,true,true,
            true,true, SignAlgoKeyRelationRepairMode.SIGN_ALGO_BASED,false);
    }
    
    public static RepairChainConfig createSignOnlyConfig() {
        return new RepairChainConfig(false,false,false,
            false,false, SignAlgoKeyRelationRepairMode.NONE,true);
    }
    
    public static RepairChainConfig createDoNothingConfig() {
        return new RepairChainConfig(false,false,false,
            false,false, SignAlgoKeyRelationRepairMode.NONE,false);
    }
    
    private boolean repairIssuer = true;
    
    private boolean repairAuthorityKeyIdentifier = true;
    
    private boolean repairCABit = true;
    
    private boolean repairPathLen = true;
    
    private boolean repairKeyUsage = true;
    
    private SignAlgoKeyRelationRepairMode repairSignAlgoKeyRelation = SignAlgoKeyRelationRepairMode.SIGN_ALGO_BASED;
    
    private boolean computeChainSignatureAfterRepair = true;
    
    public RepairChainConfig(){
    }
    
    public RepairChainConfig(boolean repairIssuer, boolean repairAuthorityKeyIdentifier,
            boolean repairCABit, boolean repairPathLen, boolean repairKeyUsage,
            SignAlgoKeyRelationRepairMode repairSignAlgoKeyRelation, boolean computeChainSignatureAfterRepair ){
        this.repairIssuer = repairIssuer;
        this.repairAuthorityKeyIdentifier = repairAuthorityKeyIdentifier;
        this.repairCABit = repairCABit;
        this.repairPathLen = repairPathLen;
        
        this.repairKeyUsage = repairKeyUsage;
        this.repairSignAlgoKeyRelation = repairSignAlgoKeyRelation;
        this.computeChainSignatureAfterRepair = computeChainSignatureAfterRepair; 
        
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

    @Override
    public String toString() {
        return "RepairChainConfig{" + "repairIssuer=" + repairIssuer + ", repairAuthorityKeyIdentifier=" + repairAuthorityKeyIdentifier + ", repairCABit=" + repairCABit + ", repairPathLen=" + repairPathLen + ", repairKeyUsage=" + repairKeyUsage + ", repairSignAlgoKeyRelation=" + repairSignAlgoKeyRelation + ", computeChainSignatureAfterRepair=" + computeChainSignatureAfterRepair + '}';
    }
    
   
    
}
