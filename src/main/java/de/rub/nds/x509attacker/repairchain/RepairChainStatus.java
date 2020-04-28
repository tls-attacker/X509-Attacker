
package de.rub.nds.x509attacker.repairchain;

/**
 *
 * @author josh
 */
public class RepairChainStatus {
    
    private boolean repairChainSuccess;
    
    private String repairChainStatusMessage;

    public RepairChainStatus(boolean repairChainSuccess, String repairChainStatusMessage) {
        this.repairChainSuccess = repairChainSuccess;
        this.repairChainStatusMessage = repairChainStatusMessage;
    }

    public boolean isRepairChainSuccess() {
        return repairChainSuccess;
    }

    public void setRepairChainSuccess(boolean repairChainSuccess) {
        this.repairChainSuccess = repairChainSuccess;
    }

    public String getRepairChainStatusMessage() {
        return repairChainStatusMessage;
    }

    public void setRepairChainStatusMessage(String repairChainStatusMessage) {
        this.repairChainStatusMessage = repairChainStatusMessage;
    }

    @Override
    public String toString() {
        return "RepairChainStatus{" + "repairChainSuccess=" + repairChainSuccess + ", repairChainStatusMessage= \n" + repairChainStatusMessage + '}';
    }
    
    
    
}
