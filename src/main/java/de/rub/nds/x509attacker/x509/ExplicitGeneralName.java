
package de.rub.nds.x509attacker.x509;

import de.rub.nds.asn1.model.Asn1Explicit;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;
import de.rub.nds.asn1.translator.X509Translator;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1ExplicitFT;

/**

 *  Explicit Container for GeneralName
 * 
 */
public class ExplicitGeneralName extends X509Model<Asn1Explicit> {
            
    private static final String type = "";    
    
    public GeneralName generalName;        
            
    
    
    public static ExplicitGeneralName getInstance(IntermediateAsn1Field intermediateAsn1Field, String identifier){
        
        return new ExplicitGeneralName(intermediateAsn1Field, identifier);
        
    }
    
    private ExplicitGeneralName(IntermediateAsn1Field intermediateAsn1Field, String identifier)
    {
        asn1 = (Asn1Explicit) X509Translator.translateSingleIntermediateField(intermediateAsn1Field, Asn1ExplicitFT.class , "explicit" + identifier, "explicit");
        if(intermediateAsn1Field.getChildren().size() == 1)
        {
            generalName = GeneralName.getInstance(intermediateAsn1Field.getChildren().get(0), identifier);            
        }
        asn1.addChild(generalName.asn1);   
        
    }  
     
}
