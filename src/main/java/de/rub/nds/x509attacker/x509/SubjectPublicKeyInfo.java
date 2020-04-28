
package de.rub.nds.x509attacker.x509;

import de.rub.nds.asn1.model.Asn1EncapsulatingBitString;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;
import de.rub.nds.asn1.translator.X509Translator;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1EncapsulatingBitStringFT;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1SequenceFT;

/**
 * 
 * SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *      algorithm            AlgorithmIdentifier,
 *      subjectPublicKey     BIT STRING  }
 *
 */
public class SubjectPublicKeyInfo extends X509Model<Asn1Sequence> {
    
    
    private static final String type = "SubjectPublicKeyInfo";
    
    public AlgorithmIdentifier algorithm;
    public Asn1EncapsulatingBitString subjectPublicKey;
    
    
    public static SubjectPublicKeyInfo getInstance(IntermediateAsn1Field intermediateAsn1Field, String identifier){
        
        return new SubjectPublicKeyInfo(intermediateAsn1Field, identifier);
        
    }
    
    private SubjectPublicKeyInfo(IntermediateAsn1Field intermediateAsn1Field, String identifier)
    {
        asn1 = (Asn1Sequence) X509Translator.translateSingleIntermediateField(intermediateAsn1Field, Asn1SequenceFT.class , identifier, type);
        
        algorithm = AlgorithmIdentifier.getInstance(intermediateAsn1Field.getChildren().get(0), "algorithm");
        asn1.addChild(algorithm.asn1); 
        
        //TODO: SubjectPublicKey ist abhängig vom OID im AlgorithmIdentifier, 
        subjectPublicKey = (Asn1EncapsulatingBitString) X509Translator.translateSingleIntermediateField(intermediateAsn1Field.getChildren().get(1), Asn1EncapsulatingBitStringFT.class, "subjectPublicKey", "");     
        asn1.addChild(subjectPublicKey);
        
    }  
     
    
}
