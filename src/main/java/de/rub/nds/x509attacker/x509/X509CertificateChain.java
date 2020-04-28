
package de.rub.nds.x509attacker.x509;


import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1Boolean;
import de.rub.nds.asn1.model.Asn1Field;
import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1PrimitiveBitString;
import de.rub.nds.asn1.model.Asn1PrimitiveOctetString;
import de.rub.nds.asn1.model.Asn1PrimitivePrintableString;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayExplicitValueModification;
import de.rub.nds.x509attacker.X509Attributes;
import de.rub.nds.x509attacker.constants.X509CertChainOutFormat;
import de.rub.nds.x509attacker.exceptions.RepairChainException;
import de.rub.nds.x509attacker.exceptions.X509ModificationException;
import de.rub.nds.x509attacker.fileystem.CertificateFileWriter;
import de.rub.nds.x509attacker.repairchain.RepairChain;
import de.rub.nds.x509attacker.repairchain.RepairChainConfig;
import de.rub.nds.x509attacker.repairchain.RepairChainStatus;
import de.rub.nds.x509attacker.x509.serializer.X509CertificateChainSerializer;
import de.rub.nds.x509attacker.x509.serializer.X509CertificateSerializer;
import de.rub.nds.x509attacker.xmlsignatureengine.XmlSignatureEngineException;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import javax.xml.bind.JAXBException;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.stream.XMLStreamException;

/**
* Represent one X509CertificateChain containing multiple X509Certificates and provides
* an API for accessing and modifying the chain.
*/
@XmlRootElement(name = "X509CertificateChain")
@XmlAccessorType(XmlAccessType.FIELD)
public class X509CertificateChain {
    private static final Logger LOGGER = LogManager.getLogger(X509CertificateChain.class);
    
    
    //represents the certificate chain ([0] = root_cert, ..., [last] =  leaf_cert)
    @XmlElementWrapper(name="X509Certificates")
    @XmlElement(name= "X509Certificate")    
    @HoldsModifiableVariable    
    private List<X509Certificate> certificateChain = new LinkedList<>();

    
    
    public X509CertificateChain()
    {           
    }
    
    public X509CertificateChain(List<X509Certificate> certChain)
    {   
        this.certificateChain = certChain;
    }
    
    public void addCertificate(int index, X509Certificate certificate)
    {
        certificateChain.add(index, certificate);        
    }
    
    public void addCertificate(X509Certificate certificate)
    {
        certificateChain.add(certificate);
    }
    
    public void removeCertificate(int index)
    {
        certificateChain.remove(index);
    }
    
    public int size()
    {
        return certificateChain.size();
    }
    
    public X509Certificate getCertificate(int index)
    {
        if(index <= certificateChain.size()-1)
        {
            return certificateChain.get(index);
        }
        else
        {
            return null;
        } 
    }
    
    public List<X509Certificate> getCertificateChain()
    {
        return certificateChain;
    }

    public void setCertificateChain(List<X509Certificate> certificateChain)
    {
        this.certificateChain = certificateChain;
    }
    
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        
        final X509CertificateChain other = (X509CertificateChain) obj;
        
        if (certificateChain.size() != other.certificateChain.size()) {
            return false;
        }
        for (int i = 0; i < certificateChain.size(); i++) {
            if (!certificateChain.get(i).equals(other.certificateChain.get(i))) {
                return false;
            }
        }
        return true;
    }
    
    @Override
    public int hashCode() {
        int hash = 7;
        Iterator i = certificateChain.iterator();
        while (i.hasNext()) {
            Object obj = i.next();
            hash = 61*hash + (obj==null ? 0 : obj.hashCode());
        }
  
  
        return hash;
    }
    
    /**
    * Computes the signature of all X509Certificate in the chain.
    * For one signature computation of a certificate the private Key from the parent certificate is used.
    * It skips the computation of one signature, if the signature engine throws an exception
    */ 
    public void signAllCertificates() throws XmlSignatureEngineException
    {
        boolean error = false;
        StringBuilder errorMessage = new StringBuilder();
        if(certificateChain.size() >= 1)
        {
            //Selfsign of root
            try{
                certificateChain.get(0).signCertificate(certificateChain.get(0).getKeyInfo());
            } catch( XmlSignatureEngineException e) {
                LOGGER.warn("- signAllCertificates(): signature computation of certificate: 0 failed: " + e);
                error = true;
                errorMessage.append("signature computation of certificate: 0 failed: " + e + "\n");
                
            }
            
            //Sign of intermediate and leaf
            for(int i=1; i<= certificateChain.size()-1; i++)
            {
                try{
                    certificateChain.get(i).signCertificate(certificateChain.get(i-1).getKeyInfo());
                } catch( XmlSignatureEngineException e) {
                    LOGGER.warn("- signAllCertificates(): signature computation of certificate: " + i + " failed: " + e);
                    error = true;
                    errorMessage.append("signature computation of certificate: " + i + " failed: " + e + "\n");
                }
                
            }
        }
        
        if(error==true)
        {
            throw new XmlSignatureEngineException(errorMessage.toString());
        }
    }
    
    
    /**
    * Repairs the chain of certificates such that all X509Certificates in the chain form a valid cerificate chain.It uses the default RepairChainConfig (which repairs all and recomputes the signature).
    * It repairs the issuer, the AuthorityKeyIdentifer, the CABit, the PathLen, the KeyUsage,
    * the SignatureAlgo / key relation.
    *
    * @return RepairChainStatus A status report about the succcess of the repair
    * 
    */
    public RepairChainStatus repairAndSignChain ()
    {
        return RepairChain.repair(RepairChainConfig.createRepairAllAndSignConfig(), this);        
    }
    
    
    /**
    * Repairs the chain of certificates depending on the given RepairChainConfig.
    * 
    * @param repairConfig the RepairChainConfig which is used
    * @return RepairChainStatus A status report about the succcess of the repair
    */
    public RepairChainStatus repairChain(RepairChainConfig repairConfig)
    {
        return RepairChain.repair(repairConfig, this);        
    }

    
    /**
    * Writes all X509Certificates of the chain as certificateFile in .pem format to the given directory.
    * 
    * 
    * @param directory The path to the directory.
    * @param outFormat The type how the certificates are divided into different certificateFiles.
 CHAIN_ALL_IND_ROOT_TO_LEAF: each X509Certificates in his own certificateFile (certificate_x.pem)
 CHAIN_COMBINED: all X509Certificates combined in one certificateFile (certificate_chain.pem)
 CHAIN_GROUPED3: three certificateFiles one for root, one for the intermediates and one for the leaf certificate (root_cert.pem, inter_certs.pem, leaf_cert.pem)
 CHAIN_GROUPED2: two certificateFiles one for root and one for the intermediates together with the leaf certificate (root_cert.pem, inter_leaf_certs.pem)
    * @return List of created Files
    *  
    */
    public List<File> writeCertificateChainToFile(String directory, X509CertChainOutFormat outFormat)
    {       
        List<File> outputFiles = new LinkedList<>();
        //TOOD: to decide if the attribute "attachToCertificateList" on the Asn1Sequence "certificate" should be considerate here too, 
        //or is it enough, when it is done in the encoding of a certificate
        switch (outFormat) {
            
            //Single Cert per file
            case ROOT_CERT:
                if(certificateChain.size()>=1){
                    outputFiles.add(certificateChain.get(0).writeCertificate(directory, "root_cert"));
                }               
                break;
            
            case LEAF_CERT:
                //only if the chain has at least two certificate and there is a leaf certificate
                if(certificateChain.size()>=2){
                    outputFiles.add(certificateChain.get(certificateChain.size()-1).writeCertificate(directory, "leaf_cert"));
                }
                
                break;
                
            case INTER_CERTS:
                //only if the chain has at least three certificate and there are intermediate certs
                if(certificateChain.size()>=3){

                    certificateChain.subList(1, certificateChain.size()-1).
                            forEach(x -> 
                                    outputFiles.add(
                                            x.writeCertificate(directory, "inter_cert_"+ (certificateChain.indexOf(x)-1))
                                    ));
                        
                }
                break;
                    
            //multiple certs combined into one file
            case INTER_CERTS_COMBINED:
                //only if the chain has at least three certificate and there are intermediate certs
                if(certificateChain.size()>=3){
                    try {    
                        String filename = "inter_certs.pem";
                        CertificateFileWriter certificateChainFileWriter = new CertificateFileWriter(directory, filename);
                        for (X509Certificate cert: certificateChain.subList(1, certificateChain.size()-1)) {

                            // Append certificate to certificate chain file
                            certificateChainFileWriter.writeCertificate(cert.getEncodedCertificate());

                        }
                        certificateChainFileWriter.close();
                        
                        outputFiles.add(new File(directory + "/" + filename));
                    } catch (IOException ex) {
                        LOGGER.error("Error writing CertificateChain to PEM: " + ex);
                    }                        
                }
                break;
            
            case INTER_LEAF_CERTS_COMBINED:
                //only if the chain has at least two certificate and there is atleast a leaf certificate and maybe further intermediate certs
                if(certificateChain.size()>=2){
                    try {    
                        String filename = "inter_leaf_certs.pem";
                        CertificateFileWriter certificateChainFileWriter = new CertificateFileWriter(directory, filename);
                        for (X509Certificate cert: certificateChain.subList(1, certificateChain.size())) {

                            // Append certificate to certificate chain file
                            certificateChainFileWriter.writeCertificate(cert.getEncodedCertificate());

                        }
                        certificateChainFileWriter.close();
                        
                        outputFiles.add(new File(directory + "/" + filename));
                    } catch (IOException ex) {
                        LOGGER.error("Error writing CertificateChain to PEM: " + ex);
                    } 
                }               
                break;
            
            case ROOT_INTER_LEAF_CERTS_COMBINED:
                //only if the chain has at least one certificate and there is atleast a root certificate
                if(certificateChain.size()>=1){
                    
                    try {
                        String filename = "root_inter_leaf_certs_combined.pem";
                        CertificateFileWriter certificateChainFileWriter = new CertificateFileWriter(directory, filename);
                        for (X509Certificate cert: certificateChain) {
                            certificateChainFileWriter.writeCertificate(cert.getEncodedCertificate());
                        }
                        certificateChainFileWriter.close();
                    } catch (IOException ex) {
                        LOGGER.error("Error writing CertificateChain to PEM: " + ex);
                    }
                }               
                break;
                
                
            case CHAIN_ALL_IND_ROOT_TO_LEAF:
                
                outputFiles.addAll(writeCertificateChainToFile(directory, X509CertChainOutFormat.ROOT_CERT));
                outputFiles.addAll(writeCertificateChainToFile(directory, X509CertChainOutFormat.INTER_CERTS));
                outputFiles.addAll(writeCertificateChainToFile(directory, X509CertChainOutFormat.LEAF_CERT));                               
                break;
                
            case CHAIN_COMBINED:
                
                
                outputFiles.addAll(writeCertificateChainToFile(directory, X509CertChainOutFormat.ROOT_INTER_LEAF_CERTS_COMBINED));
                break;
                
                
            case CHAIN_GROUPED3:
                
                outputFiles.addAll(writeCertificateChainToFile(directory, X509CertChainOutFormat.ROOT_CERT));
                outputFiles.addAll(writeCertificateChainToFile(directory, X509CertChainOutFormat.INTER_CERTS_COMBINED));
                outputFiles.addAll(writeCertificateChainToFile(directory, X509CertChainOutFormat.LEAF_CERT));
                break;
                
            case CHAIN_GROUPED2:
                
                outputFiles.addAll(writeCertificateChainToFile(directory, X509CertChainOutFormat.ROOT_CERT));
                outputFiles.addAll(writeCertificateChainToFile(directory, X509CertChainOutFormat.INTER_LEAF_CERTS_COMBINED));
                break;
                
            default: 
                break;
                
        }     
        
        
        //TOOD oder einfach leere liste zurückgeben?
        //if(outputFiles.size() == 0) return null;
        return outputFiles;
    }
    
    /**
     * Returns a deep copy of this X509CertificateChain
     *
     * @return a deep Copy of this X509CertificateChain.
     */
    public X509CertificateChain getCopy() throws JAXBException, IOException, XMLStreamException
    {
        return X509CertificateChainSerializer.copyX509CertificateChain(this);
    }
    
}
