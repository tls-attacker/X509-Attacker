
package de.rub.nds.x509attacker.repairchain;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1Boolean;
import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1PrimitiveBitString;
import de.rub.nds.asn1.model.Asn1PrimitiveOctetString;
import de.rub.nds.modifiablevariable.util.RandomHelper;
import de.rub.nds.signatureengine.SignatureEngine;
import de.rub.nds.signatureengine.keyparsers.KeyType;
import de.rub.nds.x509attacker.exceptions.RepairChainException;
import de.rub.nds.x509attacker.exceptions.X509ModificationException;
import de.rub.nds.x509attacker.helper.KeyFactory;
import de.rub.nds.x509attacker.x509.X509Certificate;
import de.rub.nds.x509attacker.x509.X509CertificateChain;
import de.rub.nds.x509attacker.xmlsignatureengine.XmlSignatureEngineException;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.util.List;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author josh
 * 
 * Helper class to repair a X509certificate chain regarding different repair configurations
 */
public class RepairChain {
    
    private static final Logger LOGGER = LogManager.getLogger(RepairChain.class);
    
    
    public static RepairChainStatus repair(RepairChainConfig repairConfig , X509CertificateChain chain)
    {
        LOGGER.trace("repair chain started (" + repairConfig.toString() + ")");
        boolean error = false;
        StringBuilder statusMessage = new StringBuilder();        
        
        if(repairConfig.isRepairIssuer()) {
            try {
                repairIssuer(chain);
                statusMessage.append("repair Issuer: success").append("\n");
            }
            catch(RepairChainException e) {
                error = true;
                statusMessage.append("repair Issuer: failed => \n").append(e).append("\n");
            }   
        }

        if(repairConfig.isRepairAuthorityKeyIdentifier()) {                
            try {
                repairAuthorityKeyIdentifier(chain);
                statusMessage.append("repair AuthorityKeyIdentifier: success").append("\n");
            }
            catch(RepairChainException e) {
                error = true;
                statusMessage.append("repair AuthorityKeyIdentifier: failed => \n").append(e).append("\n");
            }
        }

        if(repairConfig.isRepairCABit()) {
            try {
                repairCABit(chain);
                statusMessage.append("repair CABit: success").append("\n");
            }
            catch(RepairChainException e) {
                error = true;
                statusMessage.append("repair CABit: failed => \n").append(e).append("\n");
            }
        }

        if(repairConfig.isRepairPathLen()) {
            try {
                repairPathLen(chain);
                statusMessage.append("repair PathLen: success").append("\n");
            }
            catch(RepairChainException e) {
                error = true;
                statusMessage.append("repair PathLen: failed => \n").append(e).append("\n");
            }

        }

        if(repairConfig.isRepairKeyUsage()) {                
            try {
                repairKeyUsage(chain);
                statusMessage.append("repair KeyUsage: success").append("\n");
            }
            catch(RepairChainException e) {
                error = true;
                statusMessage.append("repair RepairKeyUsage: failed => \n").append(e).append("\n");
            }
        }

        if(repairConfig.getRepairSignAlgoKeyRelation() != RepairChainConfig.SignAlgoKeyRelationRepairMode.NONE) {                
            try {
                repairSignAlgoKeyRelation(chain, repairConfig);
                statusMessage.append("repair SignAlgoKeyRelation: success").append("\n");
            }
            catch(RepairChainException e) {
                error = true;
                statusMessage.append("repair SignAlgoKeyRelation: failed => \n").append(e).append("\n");
            }
        }

        if(repairConfig.isComputeChainSignatureAfterRepair()) {
            try {
                chain.signAllCertificates();
                statusMessage.append("compute ChainSignature after repair: success").append("\n");
            }
            catch(XmlSignatureEngineException e) {
                error = true;
                statusMessage.append("compute ChainSignature after repair: failed => \n").append(e).append("\n");
            }

        }
        
        //TODO: Check if builder is empty an set status to RepairNotihing: success
        if(statusMessage.length() == 0)
        {
            statusMessage.append("repair do nothing: success").append("\n");
        }
        
        RepairChainStatus repairChainStatus = new RepairChainStatus(!error, statusMessage.toString());
        LOGGER.trace("repair chain finished (" + repairChainStatus.toString() + ")");
        return repairChainStatus;
    }
    
    
    private static void repairIssuer (X509CertificateChain chain) throws RepairChainException
    {
        List<X509Certificate> certificateChain = chain.getCertificateChain();
        boolean error = false;
        StringBuilder errorMessage = new StringBuilder();
        
        
        if(certificateChain.size() >= 1)
        {   
            // --- repair of root ---
            try
            { 
                //set root.issuer Field = root.subject
                certificateChain.get(0).getIdentifierMap()
                        .setElementByIDPath("/certificate/tbsCertificate/issuer", certificateChain.get(0).getIdentifierMap().getCopyByIDPath("/certificate/tbsCertificate/subject"));

            } catch (X509ModificationException e)
            {
                error = true;
                errorMessage.append("failed to repair Issuer for certificate 0: ").append(e).append('\n');
            }
            

            // --- intermediate / leaf certificates ---
            for(int i=1; i<= certificateChain.size()-1; i++)
            {   
                try
                {
                    //set cert(i).issuer Field = cert(i-1).subject
                    certificateChain.get(i).getIdentifierMap().setElementByIDPath("/certificate/tbsCertificate/issuer", certificateChain.get(i-1).getIdentifierMap().getCopyByIDPath("/certificate/tbsCertificate/subject"));
                } catch (X509ModificationException e)
                {
                    error = true;                    
                    errorMessage.append("failed to repair Issuer for certificate " + i + ":").append(e).append('\n');
                }
                          
            }
        }
        
        if(error==true)
        {
            throw new RepairChainException(errorMessage.toString());
        }
        
    }
    
    
    
    private static void repairAuthorityKeyIdentifier (X509CertificateChain chain) throws RepairChainException
    {
        List<X509Certificate> certificateChain = chain.getCertificateChain();
        
        boolean error = false;
        StringBuilder errorMessage = new StringBuilder();
                  
        if(certificateChain.size() >= 1)
        {
            // --- repair of root ---   
            try
            { 
                //set root.AuthorityKeyIdentifier = root.SubjectKeyIdentifier
                List<String> pathsAKI = certificateChain.get(0).getIdentifierMap().getIDPathsByType("AuthorityKeyIdentifier");
                List<String> pathsSKI = certificateChain.get(0).getIdentifierMap().getIDPathsByType("SubjectKeyIdentifier");
                
                if(pathsAKI==null)
                {
                    throw new NullPointerException("AuthorityKeyIdentifier is null");
                }
                if(pathsSKI==null)
                {
                    throw new NullPointerException("SubjectKeyIdentifier is null");
                }

                if(!pathsAKI.isEmpty() && !pathsSKI.isEmpty())
                {
                    byte[] content = ((Asn1PrimitiveOctetString) certificateChain.get(0)
                            .getIdentifierMap()
                            .getElementByIDPath(pathsSKI.get(0)))
                            .getValue();

                    ((Asn1PrimitiveOctetString) certificateChain.get(0)
                            .getIdentifierMap()
                            .getElementByIDPath(pathsAKI.get(0)+"/keyIdentifier"))
                            .setValue(content);
                }
                
            } catch (NullPointerException e)
            {
                error = true;
                errorMessage.append("failed to repair AKI for certificate 0: ").append(e).append('\n');
            }


            // --- repair of intermediate / leaf certificates ---
            for(int i=1; i<= certificateChain.size()-1; i++)
            {   
                try
                { 
                    //set cert(i).AuthorityKeyIdentifier = cert(i-1).SubjectKeyIdentifier from ParentCertificate
                    List<String> pathsAKI = certificateChain.get(i).getIdentifierMap().getIDPathsByType("AuthorityKeyIdentifier");
                    List<String> pathsSKI = certificateChain.get(i-1).getIdentifierMap().getIDPathsByType("SubjectKeyIdentifier");
                    
                    if(pathsAKI==null)
                    {
                        throw new NullPointerException("AuthorityKeyIdentifier is null");
                    }
                    if(pathsSKI==null)
                    {
                        throw new NullPointerException("SubjectKeyIdentifier is null");
                    }
                
                    if(!pathsAKI.isEmpty() && !pathsSKI.isEmpty())
                    {
                        byte[] content = ((Asn1PrimitiveOctetString) certificateChain.get(i-1)
                                .getIdentifierMap()
                                .getElementByIDPath(pathsSKI.get(0)))
                                .getValue();

                        ((Asn1PrimitiveOctetString) certificateChain.get(i)
                                .getIdentifierMap()
                                .getElementByIDPath(pathsAKI.get(0)+"/keyIdentifier"))
                                .setValue(content);
                    }
                
                } catch (NullPointerException e)
                {
                    error = true;
                    errorMessage.append("failed to repair AKI for certificate " + i + ":").append(e).append('\n');
                }
                             
            }
        }
        
        
        if(error==true)
        {
            throw new RepairChainException(errorMessage.toString());
        }
    }
    
    
    private static void repairCABit (X509CertificateChain chain) throws RepairChainException
    {
        List<X509Certificate> certificateChain = chain.getCertificateChain();
        boolean error = false;
        StringBuilder errorMessage = new StringBuilder();
        
        
        if(certificateChain.size() >= 1)
        {
            // --- repair of root ---   
            try
            {
                //set root.CABit
                List<String> pathsBasicConstraints = certificateChain.get(0).getIdentifierMap().getIDPathsByType("BasicConstraints");
                if(pathsBasicConstraints==null)
                {
                    throw new NullPointerException("BasicConstraints is null");
                }
                if(!pathsBasicConstraints.isEmpty())
                {
                    Asn1Boolean asn1Ca = (Asn1Boolean) certificateChain.get(0).getIdentifierMap().getElementByIDPath(pathsBasicConstraints.get(0) + "/ca");
                    if(asn1Ca != null) {
                        asn1Ca.setValue(true);
                    }
                    else
                    {
                        Asn1Boolean newAsn1CA = new Asn1Boolean();
                        newAsn1CA.setValue(true);
                        newAsn1CA.setIdentifier("ca");
                        certificateChain.get(0).getIdentifierMap()
                                .setElementByIDPath(pathsBasicConstraints.get(0) + "/ca", newAsn1CA);

                    }
                }
            } catch (NullPointerException | X509ModificationException e)
            {   
                error = true;
                errorMessage.append("failed to repair CABit for certificate 0:").append(e).append('\n');
            }


            // --- repair of intermediate / leaf certificates ---
            for(int i=1; i<= certificateChain.size()-1; i++)
            {
                //(only for inter-Certs)
                if(i != certificateChain.size()) {
                    try
                    {
                        //set cert(i).setCABit
                        List<String> pathsBasicConstraints = certificateChain.get(i).getIdentifierMap().getIDPathsByType("BasicConstraints");
                        if(pathsBasicConstraints==null)
                        {
                            throw new NullPointerException("cert does not contain a BasicConstraints (is null)");
                        }
                        
                        if(!pathsBasicConstraints.isEmpty())
                        {
                            Asn1Boolean asn1Ca = (Asn1Boolean) certificateChain.get(i).getIdentifierMap().getElementByIDPath(pathsBasicConstraints.get(0) + "/ca");
                            if(asn1Ca != null) {
                                asn1Ca.setValue(true);
                            }
                            else
                            {
                                Asn1Boolean newAsn1CA = new Asn1Boolean();
                                newAsn1CA.setValue(true);
                                newAsn1CA.setIdentifier("ca");
                                certificateChain.get(i).getIdentifierMap()
                                        .setElementByIDPath(pathsBasicConstraints.get(0) + "/ca", newAsn1CA);

                            }

                        }
                    } catch (NullPointerException | X509ModificationException e)
                    {   
                        error = true;                        
                        errorMessage.append("failed to repair CABit for certificate " + i + ":").append(e).append('\n');
                    }
                }                
            }
        }
        
            
        if(error==true)
        {
            throw new RepairChainException(errorMessage.toString());
        }
    }
    
    //TODO: not sure if the pathLen Attribute must be set or if it is optional (indepentent from the ca bit) https://tools.ietf.org/html/rfc5280#section-4.2.1.9
    //currently: it does not create a pathlen asn1 element if its missing
    private static void repairPathLen (X509CertificateChain chain) throws RepairChainException
    {
        List<X509Certificate> certificateChain = chain.getCertificateChain();
        
        boolean error = false;
        StringBuilder errorMessage = new StringBuilder();
        
        if(certificateChain.size() >= 1)
        {
            // --- repair of root ---             
            try
            {
                //set root.Pathlen
                List<String> pathsBasicConstraints = certificateChain.get(0).getIdentifierMap().getIDPathsByType("BasicConstraints");
                if(pathsBasicConstraints==null)
                {
                    throw new NullPointerException("cert does not contain a BasicConstraints (is null)");
                }
                if(!pathsBasicConstraints.isEmpty())
                {
                    //CA Certificate does not have a pathlen
                    Asn1Integer asn1PathLen = (Asn1Integer) certificateChain.get(0).getIdentifierMap().getElementByIDPath(pathsBasicConstraints.get(0) + "/pathLenConstraint");
                    if(asn1PathLen != null) {
                        asn1PathLen.setValue(BigInteger.valueOf(certificateChain.size()-1));
                    }else{
                        //TODO: do not throw Error; it seems like that fixing the path len is only necessary if it is available
                        //throw new NullPointerException("cert does not contain a PathLenConstraint (is null)");
                    }
                    
                }
            
            } catch (NullPointerException e)
            {   
                error = true;
                errorMessage.append("failed to repair PathLen for certificate 0:").append(e).append('\n');
            }

            

            // --- repair of intermediate / leaf certificates ---
            for(int i=1; i<= certificateChain.size()-1; i++)
            {
                //(only for inter-Certs)
                if(i != certificateChain.size()) {
                    try
                    {
                        //set cert(i).Pathlen 
                        List<String> pathsBasicConstraints = certificateChain.get(i).getIdentifierMap().getIDPathsByType("BasicConstraints");
                        if(pathsBasicConstraints==null)
                        {
                            throw new NullPointerException("cert does not contain a BasicConstraints (is null)");
                        }
                        if(!pathsBasicConstraints.isEmpty())
                        {
                            //Intermediate Pathlen = number of maximum allowed follwoing intermediate certificates
                            Asn1Integer asn1PathLen = (Asn1Integer) certificateChain.get(i).getIdentifierMap().getElementByIDPath(pathsBasicConstraints.get(0) + "/pathLenConstraint");
                            if(asn1PathLen != null) {
                                asn1PathLen.setValue(BigInteger.valueOf(certificateChain.size()-1-i));
                            }else{
                                //TODO: do not throw Error; it seems like that fixing the path len is only necessary if it is available
                                //throw new NullPointerException("cert does not contain a PathLenConstraint (is null)");
                            }
                        }
                    } catch (NullPointerException e)
                    {   
                        error = true;
                        errorMessage.append("failed to repair PathLen for certificate " + i + ":").append(e).append('\n');
                    }
                }                
            }
        }
        
        if(error==true)
        {
            throw new RepairChainException(errorMessage.toString());
        }
        
    }
    
    private static void repairKeyUsage (X509CertificateChain chain) throws RepairChainException
    {
        List<X509Certificate> certificateChain = chain.getCertificateChain();
        
        boolean error = false;
        StringBuilder errorMessage = new StringBuilder();
        
        if(certificateChain.size() >= 1)
        {
            // --- repair of root ---   
            
            //set root.KeyUsageBit CertificateSign
            List<Asn1Encodable> keyUsageAsn1 = certificateChain.get(0).getIdentifierMap().getElementsByType("KeyUsage");

            if(keyUsageAsn1 != null && !keyUsageAsn1.isEmpty() && keyUsageAsn1.get(0) instanceof Asn1PrimitiveBitString) {
                byte[] value = ((Asn1PrimitiveBitString) keyUsageAsn1.get(0)).getValue();
                value[0] = (byte) (value[0]| (1<<2));
                ((Asn1PrimitiveBitString) keyUsageAsn1.get(0)).setValue(value);
                ((Asn1PrimitiveBitString) keyUsageAsn1.get(0)).setUnusedBits(2);
            }
            else
            {
                error = true;
                errorMessage.append("failed to repair KeyUsage for certificate 0: keyUsage is null or not Asn1PrimitiveBitString").append('\n');
            }
                
           

            // --- repair of intermediate / leaf certificates ---
            for(int i=1; i<= certificateChain.size()-1; i++)
            {
                //(only for inter-Certs)
                if(i != certificateChain.size()) {
                    
                    //set cert(i).KeyUsageBit CertificateSign
                    keyUsageAsn1 = certificateChain.get(i).getIdentifierMap().getElementsByType("KeyUsage");

                    if(keyUsageAsn1 != null && !keyUsageAsn1.isEmpty() && keyUsageAsn1.get(0) instanceof Asn1PrimitiveBitString) {
                        byte[] value = ((Asn1PrimitiveBitString) keyUsageAsn1.get(0)).getValue();
                        value[0] = (byte) (value[0]| (1<<2));
                        ((Asn1PrimitiveBitString) keyUsageAsn1.get(0)).setValue(value);
                        ((Asn1PrimitiveBitString) keyUsageAsn1.get(0)).setUnusedBits(2);
                    } 
                    else
                    {
                        error = true;
                        errorMessage.append("failed to repair KeyUsage for certificate " + i + ": keyUsage is null or not Asn1PrimitiveBitString").append('\n');
                    }        

                }                
            }
        }
        
        if(error==true)
        {
            throw new RepairChainException(errorMessage.toString());
        }
        
    }
    
    
    private static void repairSignAlgoKeyRelation(X509CertificateChain chain, RepairChainConfig repairConfig) throws RepairChainException
    {
        RepairChainConfig.SignAlgoKeyRelationRepairMode repairMode = repairConfig.getRepairSignAlgoKeyRelation();
        List<X509Certificate> certificateChain = chain.getCertificateChain();
        
        boolean error = false;
        StringBuilder errorMessage = new StringBuilder();
        
        if(certificateChain.isEmpty())
        {
            errorMessage.append("chain is empty").append('\n');
            throw new RepairChainException(errorMessage.toString());
        }
        
        if(repairMode == RepairChainConfig.SignAlgoKeyRelationRepairMode.KEY_BASED)
        {
            // --- repair Root Cert ---
            try
            {
                //extract keyType of key
                KeyType keyType = certificateChain.get(0).getKeyInfo().getKeyType();

                //extract keyType of currently effective SignAlgo
                String effSignOID = certificateChain.get(0).getEffectiveSignatureOID();
                KeyType keyTypeSignAlgo = SignatureEngine.getEngineTupelForOID(effSignOID).keyType; 

                if(!keyType.equals(keyTypeSignAlgo))
                {
                    List<SignatureEngine.EngineTupel> listOfCompatibleEngines = SignatureEngine.getEngineTupelForKeyType(keyType);
                    Random random = RandomHelper.getRandom();
                    String engineOID = listOfCompatibleEngines.get(random.nextInt(listOfCompatibleEngines.size())).objectIdentifierString;

                    //set choosen SignatureEngine in cert i+1
                    certificateChain.get(0).getSignatureInfo().setSignatureAlgorithmOidValue(engineOID);
                }
                
            } catch (NullPointerException e)
            {   
                error = true;
                errorMessage.append("failed to repair SignAlgoKeyRelation for certificate 0:").append(e).append('\n');
            }  
                
            // --- repair Intermediate / Leaf Cert ---
            for(int i=0; i< certificateChain.size()-1; i++)
            {
                try
                {
                    //extract keyType of key
                    KeyType keyType = certificateChain.get(i).getKeyInfo().getKeyType();

                    //extract keyType of currently effective SignAlgo
                    String effSignOID = certificateChain.get(i+1).getEffectiveSignatureOID();
                    KeyType keyTypeSignAlgo = SignatureEngine.getEngineTupelForOID(effSignOID).keyType; 

                    if(!keyType.equals(keyTypeSignAlgo))
                    {
                        List<SignatureEngine.EngineTupel> listOfCompatibleEngines = SignatureEngine.getEngineTupelForKeyType(keyType);
                        Random random = RandomHelper.getRandom();
                        String engineOID = listOfCompatibleEngines.get(random.nextInt(listOfCompatibleEngines.size())).objectIdentifierString;

                        //set choosen SignatureEngine in cert i+1
                        certificateChain.get(i+1).getSignatureInfo().setSignatureAlgorithmOidValue(engineOID);
                    }
                } catch (NullPointerException e)
                {   
                    error = true;
                    errorMessage.append("failed to repair SignAlgoKeyRelation for certificate " + i + ":").append(e).append('\n');
                }
            }
            
        } else if(repairMode == RepairChainConfig.SignAlgoKeyRelationRepairMode.SIGN_ALGO_BASED)
        {   
            File keysResourceFolder = new File(repairConfig.getKeysResourceFolder());
            if(!keysResourceFolder.exists())
            {
                errorMessage.append("keysResourceFolder: " + repairConfig.getKeysResourceFolder() + " does not exists" ).append('\n');
                throw new RepairChainException(errorMessage.toString());
            }
            
            
            try
            {
                //extract effectiveSignOID of currently effective SignAlgo
                String effSignOID_cert0 = certificateChain.get(0).getEffectiveSignatureOID();
                
                //extract compatible keyType for cert1
                KeyType keyTypeSignAlgo_cert0 = SignatureEngine.getEngineTupelForOID(effSignOID_cert0).keyType;
                      
                
                //if the chain has two certificat, also extract effectiveSignOID of the second cert
                //cause the key of cert 0 is used to sign cert0 and cert1
                if(certificateChain.size()>1)
                {
                    String effSignOID_cert1 = certificateChain.get(1).getEffectiveSignatureOID();
                    KeyType keyTypeSignAlgo_cert1 = SignatureEngine.getEngineTupelForOID(effSignOID_cert1).keyType;
                    
                    if(!keyTypeSignAlgo_cert0.equals(keyTypeSignAlgo_cert1))
                    {
                       
                        List<SignatureEngine.EngineTupel> listOfCompatibleEngines = SignatureEngine.getEngineTupelForKeyType(keyTypeSignAlgo_cert0);
                        Random random = RandomHelper.getRandom();
                        String engineOID = listOfCompatibleEngines.get(random.nextInt(listOfCompatibleEngines.size())).objectIdentifierString;

                        //set the signAlgOid of cert 1 corresponding to the key of cert0
                        certificateChain.get(1).getSignatureInfo().setSignatureAlgorithmOidValue(engineOID);
                    }
                }

                //extract keyType of key
                KeyType keyTypeCert = certificateChain.get(0).getKeyInfo().getKeyType();    

                if(!keyTypeSignAlgo_cert0.equals(keyTypeCert))
                {  
                    //chose and set new key file
                    File keyFile = KeyFactory.getRandomKeyFile(keysResourceFolder, keyTypeSignAlgo_cert0);
                    certificateChain.get(0).setKeyFile(keyFile);
                }
                
            } catch (NullPointerException | IOException e)
            {   
                error = true;
                errorMessage.append("failed to repair SignAlgoKeyRelation for certificate 0:").append(e).append('\n');
            }     
                
            for(int i = 1; i< certificateChain.size()-1; i++)
            {
                try
                {
                    //extract keyType of currently effective SignAlgo
                    String effSignOID = certificateChain.get(i+1).getEffectiveSignatureOID();
                    KeyType keyTypeSignAlgo = SignatureEngine.getEngineTupelForOID(effSignOID).keyType;


                    //extract keyType of key
                    KeyType keyTypeCert = certificateChain.get(i).getKeyInfo().getKeyType();    

                    if(!keyTypeSignAlgo.equals(keyTypeCert))
                    { 
                        //chose and set new key file
                        File keyFile = KeyFactory.getRandomKeyFile(keysResourceFolder, keyTypeSignAlgo);
                        certificateChain.get(i).setKeyFile(keyFile);
                    }
                } catch (NullPointerException | IOException e)
                {   
                    error = true;
                    errorMessage.append("failed to repair SignAlgoKeyRelation for certificate " + i + ":").append(e).append('\n');
                }
            }
        }
        
        if(error==true)
        {
            throw new RepairChainException(errorMessage.toString());
        }
        
    }
}
