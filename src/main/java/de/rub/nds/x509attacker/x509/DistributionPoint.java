
package de.rub.nds.x509attacker.x509;

import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;
import de.rub.nds.asn1.translator.X509Translator;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1IntegerFT;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1SequenceFT;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**

 * DistributionPoint ::= SEQUENCE {
 *      distributionPoint       [0]     DistributionPointName OPTIONAL,
 *      reasons                 [1]     ReasonFlags OPTIONAL,
 *      cRLIssuer               [2]     GeneralNames OPTIONAL }
 * 
 */

public class DistributionPoint extends X509Model<Asn1Sequence> {
    
    private static final Logger LOGGER = LogManager.getLogger();     
    
    private static final String type = "DistributionPoint";
    
    public DistributionPointName distributionPointName;
    public ReasonFlags reasons;
    public GeneralNames cRLIssuer;
    
    
    public static DistributionPoint getInstance(IntermediateAsn1Field intermediateAsn1Field, String identifier){
        
        return new DistributionPoint(intermediateAsn1Field, identifier);        
    }
    
    private DistributionPoint(IntermediateAsn1Field intermediateAsn1Field, String identifier)
    {
        
        asn1 = (Asn1Sequence) X509Translator.translateSingleIntermediateField(intermediateAsn1Field, Asn1SequenceFT.class , identifier, type);
        
        
        for(IntermediateAsn1Field interFieldChild : intermediateAsn1Field.getChildren()) {
            
             switch(interFieldChild.getTagNumber())  {

                case 0: //DistributionPointName
                    distributionPointName = DistributionPointName.getInstance(interFieldChild, "distributionPointName");
                    asn1.addChild(distributionPointName.asn1);
                    break;

                case 1: //ReasonFlags
                    reasons = ReasonFlags.getInstance(interFieldChild, "reasons");
                    asn1.addChild(reasons.asn1);
                    //LOGGER.warn("Testing required: Parsing of DistributionPoint->ReasonFlags (check if explicit/implicit is correct)");
                    break;

                case 2: //GeneralNames
                    cRLIssuer = GeneralNames.getInstance(interFieldChild, "cRLIssuer");
                    asn1.addChild(cRLIssuer.asn1);
                    //LOGGER.warn("Testing required: Parsing of DistributionPoint->GeneralNames (check if explicit/implicit is correct))");
                    break;

                default:
                    LOGGER.warn("Parser Error: DistributionPoint -> Default Case triggerd; no Parser defined for Tag Number: " + interFieldChild.getTagNumber());
            }
            
        }     
    } 
    
}
