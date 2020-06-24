
package de.rub.nds.x509attacker.repairchain;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

/**
 *
 * @author josh
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class RepairChainStatus {
    
    private boolean repairChainSuccess;
    
    private String repairChainStatusMessage;

    public RepairChainStatus(boolean repairChainSuccess, String repairChainStatusMessage) {
        this.repairChainSuccess = repairChainSuccess;
        this.repairChainStatusMessage = repairChainStatusMessage;
    }

    public RepairChainStatus() {        
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
