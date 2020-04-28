
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

 * CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
 * 
 */

public class CRLDistributionPoints extends X509Model<Asn1Sequence> {
    
    private static final Logger LOGGER = LogManager.getLogger();    
    
    public static final String OID = "2.5.29.31";    
    
    private static final String type = "CRLDistributionPoints";
    
    public List<DistributionPoint> distributionPoint ;
    
    
    public static CRLDistributionPoints getInstance(IntermediateAsn1Field intermediateAsn1Field, String identifier){
        
        return new CRLDistributionPoints(intermediateAsn1Field, identifier);        
    }
    
    private CRLDistributionPoints(IntermediateAsn1Field intermediateAsn1Field, String identifier)
    {
        
        asn1 = (Asn1Sequence) X509Translator.translateSingleIntermediateField(intermediateAsn1Field, Asn1SequenceFT.class , identifier, type);
        
        distributionPoint = new LinkedList<>();
        int index = 0;
        for(IntermediateAsn1Field interFieldChild : intermediateAsn1Field.getChildren()) {
            distributionPoint.add(DistributionPoint.getInstance(interFieldChild, "distributionPoint"+index++));
            asn1.addChild(distributionPoint.get(distributionPoint.size()-1).asn1);
        } 
    } 
    
}
