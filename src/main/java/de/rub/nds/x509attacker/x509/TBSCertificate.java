
package de.rub.nds.x509attacker.x509;

import de.rub.nds.asn1.TagClass;
import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;
import de.rub.nds.asn1.translator.X509Translator;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1IntegerFT;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1SequenceFT;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**

 * TBSCertificate ::= SEQUENCE {
 *      version          [ 0 ]  Version DEFAULT v1(0),
 *      serialNumber            CertificateSerialNumber,
 *      signature               AlgorithmIdentifier,
 *      issuer                  Name,
 *      validity                Validity,
 *      subject                 Name,
 *      subjectPublicKeyInfo    SubjectPublicKeyInfo,
 *      issuerUniqueID    [ 1 ] IMPLICIT UniqueIdentifier OPTIONAL,
 *      subjectUniqueID   [ 2 ] IMPLICIT UniqueIdentifier OPTIONAL,
 *      extensions        [ 3 ] Extensions OPTIONAL
 *      }
 * 
 */
public class TBSCertificate extends X509Model<Asn1Sequence>{
    
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String type = "TBSCertificate";
    
    public Version version;
    public Asn1Integer serialNumber;
    public AlgorithmIdentifier signature;
    public Name issuer;    
    public Validity validity;
    public Name subject;
    public SubjectPublicKeyInfo subjectPublicKeyInfo;
    //public UniqueIdentifier issuerUniqueID
    //public UniqueIdentifier subjecUniqueID
    public ExplicitExtensions explicitExtensions;
     
    
    
    public static TBSCertificate getInstance(IntermediateAsn1Field intermediateAsn1Field, String identifier){
        
        return new TBSCertificate(intermediateAsn1Field, identifier);
        
    }
    
    private TBSCertificate(IntermediateAsn1Field intermediateAsn1Field, String identifier)
    {
        this.asn1 = (Asn1Sequence) X509Translator.translateSingleIntermediateField(intermediateAsn1Field, Asn1SequenceFT.class , identifier, type);
        
        int index = 0;
        if(intermediateAsn1Field.getChildren().size() > 1)
        {
                        
            //version - can be optional
            if(intermediateAsn1Field.getChildren().get(0).getTagClass() == TagClass.CONTEXT_SPECIFIC.getIntValue() && intermediateAsn1Field.getChildren().get(0).getTagNumber() == 0) {
                version = Version.getInstance(intermediateAsn1Field.getChildren().get(index++), "version");
                asn1.addChild(version.asn1);
            }
            
            //serialNumber
            serialNumber = (Asn1Integer) X509Translator.translateSingleIntermediateField(intermediateAsn1Field.getChildren().get(index++), Asn1IntegerFT.class , "serialNumber", "CertificateSerialNumber");
            asn1.addChild(serialNumber); 
            
            
            //signature
            signature = AlgorithmIdentifier.getInstance(intermediateAsn1Field.getChildren().get(index++), "signature");
            asn1.addChild(signature.asn1);
            
            //issuer
            issuer = Name.getInstance(intermediateAsn1Field.getChildren().get(index++), "issuer");
            asn1.addChild(issuer.asn1);
            
            //validity
            validity = Validity.getInstance(intermediateAsn1Field.getChildren().get(index++), "validity");
            asn1.addChild(validity.asn1);
            
            //subject
            subject = Name.getInstance(intermediateAsn1Field.getChildren().get(index++), "subject");
            asn1.addChild(subject.asn1);
                    
            //subjectPublicKeyInfo
            subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(intermediateAsn1Field.getChildren().get(index++), "subjectPublicKeyInfo");
            asn1.addChild(subjectPublicKeyInfo.asn1);
            
                        
            int amountOptionalFields = intermediateAsn1Field.getChildren().size() - index;
            while(amountOptionalFields > 0) {
                
                switch(intermediateAsn1Field.getChildren().get(index).getTagNumber())  {
                    
                    case 1://issuerUniqueID
                        //TODO: entweder erwetiern, oder Logger warnung ausgeben und Überspringen
                        LOGGER.warn("Not Implemented: GeneralName -> Parsing Tag 1 'issuerUniqueID'");
                        break;
                        
                    case 2: //subjecUniqueID
                        LOGGER.warn("Not Implemented: TBSCertificate -> Parsing Tag 2 'subjecUniqueID'");
                        break;
                        
                    case 3: //extensions
                        explicitExtensions = ExplicitExtensions.getInstance(intermediateAsn1Field.getChildren().get(index++), "explicitExtensions");
                        asn1.addChild(explicitExtensions.asn1);
                        break;
                        
                    default:
                        LOGGER.warn("Parser Error: TBSCertificate -> Default Case triggerd; no Parser defined for Tag Number: " + intermediateAsn1Field.getChildren().get(index).getTagNumber());
                        
                } 
                        
                amountOptionalFields--;
            }
            
        }
        
        
    }  
    
    
    public void setIssuer(Name newIssuer) {    
        
        asn1.getChildren().set(asn1.getChildren().indexOf(issuer.asn1), newIssuer.asn1);
        this.issuer = newIssuer;
        issuer.asn1.setIdentifier("issuer");
    }
     
    
}
