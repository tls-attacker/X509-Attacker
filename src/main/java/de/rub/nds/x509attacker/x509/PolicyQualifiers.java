
package de.rub.nds.x509attacker.x509;

import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;
import de.rub.nds.asn1.translator.X509Translator;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1SequenceFT;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**

 * policyQualifiers   SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo OPTIONAL
 * 
 */

public class PolicyQualifiers extends X509Model<Asn1Sequence> {
    
    private static final Logger LOGGER = LogManager.getLogger();    
    
    private static final String type = "PolicyQualifiers";
    
    public List<PolicyQualifierInfo> policyQualifierInfo;
    
    
    public static PolicyQualifiers getInstance(IntermediateAsn1Field intermediateAsn1Field, String identifier){
        
        return new PolicyQualifiers(intermediateAsn1Field, identifier);        
    }
    
    private PolicyQualifiers(IntermediateAsn1Field intermediateAsn1Field, String identifier)
    {
        
        asn1 = (Asn1Sequence) X509Translator.translateSingleIntermediateField(intermediateAsn1Field, Asn1SequenceFT.class , identifier, type);
        
        policyQualifierInfo = new LinkedList<>();
        int index = 0;
        for(IntermediateAsn1Field interFieldChild : intermediateAsn1Field.getChildren()) {
            policyQualifierInfo.add(PolicyQualifierInfo.getInstance(interFieldChild, "policyQualifierInfo"+index++));
            asn1.addChild(policyQualifierInfo.get(policyQualifierInfo.size()-1).asn1);
        }
    } 
    
}
