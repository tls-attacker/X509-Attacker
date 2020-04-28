
package de.rub.nds.x509attacker.x509;

import de.rub.nds.asn1.TagNumber;
import de.rub.nds.asn1.model.Asn1Boolean;
import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;
import de.rub.nds.asn1.translator.X509Translator;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1BooleanFT;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1IntegerFT;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1SequenceFT;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**

 * BasicConstraints ::= SEQUENCE {
 *      cA                      BOOLEAN DEFAULT FALSE,
 *      pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
 * 
 */

public class BasicConstraints extends X509Model<Asn1Sequence> {
    
    private static final Logger LOGGER = LogManager.getLogger();    
    
    public static final String OID = "2.5.29.19";    
    
    private static final String type = "BasicConstraints";
    
    public Asn1Boolean ca;
    public Asn1Integer pathLenConstraint;
    
    
    public static BasicConstraints getInstance(IntermediateAsn1Field intermediateAsn1Field, String identifier){
        
        return new BasicConstraints(intermediateAsn1Field, identifier);        
    }
    
    private BasicConstraints(IntermediateAsn1Field intermediateAsn1Field, String identifier)
    {
        
        asn1 = (Asn1Sequence) X509Translator.translateSingleIntermediateField(intermediateAsn1Field, Asn1SequenceFT.class , identifier, type);
        
        int index = 0;
        int amountOptionalFields = intermediateAsn1Field.getChildren().size() - index;
        while(amountOptionalFields > 0) {
            
            
            //ca
            if(intermediateAsn1Field.getChildren().get(index).getTagNumber() == TagNumber.BOOLEAN.getIntValue()) {
                ca = (Asn1Boolean) X509Translator.translateSingleIntermediateField(intermediateAsn1Field.getChildren().get(index++), Asn1BooleanFT.class , "ca", "");
                asn1.addChild(ca);
            }
            
            //pathLenConstraint - can be optional
            else if(intermediateAsn1Field.getChildren().get(index).getTagNumber() == TagNumber.INTEGER.getIntValue()) {
               pathLenConstraint = (Asn1Integer) X509Translator.translateSingleIntermediateField(intermediateAsn1Field.getChildren().get(index++), Asn1IntegerFT.class , "pathLenConstraint", "");
               asn1.addChild(pathLenConstraint);
                    
            }
            else {
                LOGGER.warn("Parser Error: BasicConstraint -> Else Case triggerd; no Parser defined for Tag Number: " + intermediateAsn1Field.getChildren().get(index).getTagNumber());
            }

            amountOptionalFields--;
        
        }  
    } 
    
}
