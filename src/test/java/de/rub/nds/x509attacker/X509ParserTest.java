
package de.rub.nds.x509attacker;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.encoder.Asn1TypeRegister;
import de.rub.nds.asn1.encoder.X509Encoder;
import de.rub.nds.asn1.encoder.typeprocessors.DefaultX509TypeProcessor;
import de.rub.nds.asn1.encoder.typeprocessors.SubjectPublicKeyInfoTypeProcessor;
import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1PrimitiveBitString;
import de.rub.nds.asn1.model.Asn1PrimitivePrintableString;
import de.rub.nds.asn1.model.Asn1PseudoType;
import de.rub.nds.asn1.model.KeyInfo;
import de.rub.nds.asn1.model.SignatureInfo;
import de.rub.nds.asn1.parser.Asn1Parser;
import de.rub.nds.asn1.parser.ParserException;
import de.rub.nds.asn1.parser.X509Parser;
import de.rub.nds.asn1.parser.contentunpackers.ContentUnpackerRegister;
import de.rub.nds.asn1.parser.contentunpackers.DefaultContentUnpacker;
import de.rub.nds.asn1.parser.contentunpackers.PrimitiveBitStringUnpacker;
import de.rub.nds.asn1.translator.*;
import de.rub.nds.asn1.translator.TestExtensionsContext;
import de.rub.nds.asn1tool.Asn1Tool;
import de.rub.nds.asn1tool.xmlparser.JaxbClassList;
import de.rub.nds.x509attacker.constants.X509CertChainOutFormat;
import de.rub.nds.x509attacker.exceptions.RepairChainException;
import de.rub.nds.x509attacker.exceptions.X509ModificationException;
import de.rub.nds.x509attacker.identifiermap.IdentifierMap;
import de.rub.nds.x509attacker.keyfilemanager.KeyFileManager;
import de.rub.nds.x509attacker.keyfilemanager.KeyFileManagerException;
import de.rub.nds.x509attacker.x509.*;
import de.rub.nds.x509attacker.x509.Certificate;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.util.HashSet;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/**
 *
 * @author josh
 */
public class X509ParserTest {
   @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder(); 
   
    
    
    @Test
    public void testX509ChainParser() throws ParserException, IOException, KeyFileManagerException, RepairChainException {
        System.out.println("Test testX509ChainParser");
        
        try {
            String outputFolder= "/home/josh/GitRepos/Masterthesis/Dev_Masterthesis/Test_Zertifikate/out_generated_PEM_Certs/TestX509Attacker/CertChainTest/";
            String keyDirectory = "/home/josh/GitRepos/Masterthesis/Dev_Masterthesis/Test_Zertifikate/KeyFiles";
            
            
         
            String certFileHeise0 = "/home/josh/GitRepos/Masterthesis/Dev_Masterthesis/Test_Zertifikate/in_valid_PEM_Certs/heise_0.pem";
            String certFileHeise1 = "/home/josh/GitRepos/Masterthesis/Dev_Masterthesis/Test_Zertifikate/in_valid_PEM_Certs/heise_1.pem";
            String certFileHeise2 = "/home/josh/GitRepos/Masterthesis/Dev_Masterthesis/Test_Zertifikate/in_valid_PEM_Certs/heise_2.pem";
            
            String certGolem2File = "/home/josh/GitRepos/Masterthesis/Dev_Masterthesis/Test_Zertifikate/in_valid_PEM_Certs/golem_2.pem";
            
            String certReddit0File = "/home/josh/GitRepos/Masterthesis/Dev_Masterthesis/Test_Zertifikate/in_valid_PEM_Certs/reddit_0.pem";
            
            String certGoogle0File = "/home/josh/GitRepos/Masterthesis/Dev_Masterthesis/Test_Zertifikate/in_valid_PEM_Certs/google_0.pem";
            String certGoogle1File = "/home/josh/GitRepos/Masterthesis/Dev_Masterthesis/Test_Zertifikate/in_valid_PEM_Certs/google_1.pem";
            String certGoogle2File = "/home/josh/GitRepos/Masterthesis/Dev_Masterthesis/Test_Zertifikate/in_valid_PEM_Certs/google_2.pem";
            
            
            
            
            
            X509Parser x509Parser1 = new X509Parser(certFileHeise0);
            X509Certificate certHeise0 = x509Parser1.parse();
            
            X509Parser x509Parser2 = new X509Parser(certFileHeise1);
            X509Certificate certHeise1 = x509Parser2.parse();
            
            X509Parser x509Parser3 = new X509Parser(certFileHeise2);
            X509Certificate certHeise2 = x509Parser3.parse();
            
            
            X509Parser x509ParserGolem = new X509Parser(certGolem2File);
            X509Certificate certGolem2 = x509ParserGolem.parse();
            
            X509Parser x509ParserReddit0 = new X509Parser(certReddit0File);
            X509Certificate certReddit0 = x509ParserReddit0.parse();
            
            X509Parser x509ParserGoogle0 = new X509Parser(certGoogle0File);
            X509Certificate certGoogle0 = x509ParserGoogle0.parse();
            
            X509Parser x509ParserGoogle1  = new X509Parser(certGoogle1File);
            X509Certificate certGoogle1 = x509ParserGoogle1.parse();
            
            X509Parser x509ParserGoogle2 = new X509Parser(certGoogle2File);
            X509Certificate certGoogle2 = x509ParserGoogle2.parse();
            
            
            // Load key files
            KeyFileManager keyFileManager = KeyFileManager.getReference();
            keyFileManager.init(keyDirectory);
            
            certHeise0.setKeyFile(new File(keyDirectory + "/ecdsa-secp160k1.pem"));           
            certHeise1.setKeyFile(new File(keyDirectory + "/1-rsa2048.pem"));
            certHeise2.setKeyFile(new File(keyDirectory + "/keyDSA512.pem"));
            
            certGoogle0.getKeyInfo().setKeyFileName("1-rsa2048.pem");
            certGoogle1.getKeyInfo().setKeyFileName("1-rsa2048.pem");
            certGoogle2.getKeyInfo().setKeyFileName("1-rsa2048.pem");  
            
            certGolem2.getKeyInfo().setKeyFileName("1-rsa2048.pem");
            certReddit0.getKeyInfo().setKeyFileName("1-rsa2048.pem");
            
          
            
            X509CertificateChain certChain = new X509CertificateChain();            
            
              
            certChain.addCertificate(certHeise1);
            certChain.addCertificate(certHeise2);
            certChain.addCertificate(certGoogle1);
            
            certChain.repairAndSignChain();
            
            IdentifierMap map = certHeise0.getIdentifierMap();
            String path = tempFolder.getRoot().getPath();
            certChain.writeCertificateChainToFile(outputFolder, X509CertChainOutFormat.CHAIN_ALL_IND_ROOT_TO_LEAF);
            //certChain.writeCertificateChainToFile(outputFolder, X509CertChainOutFormat.CHAIN_COMBINED);
            certChain.writeCertificateChainToFile(outputFolder, X509CertChainOutFormat.CHAIN_GROUPED3);
            certChain.writeCertificateChainToFile(outputFolder, X509CertChainOutFormat.CHAIN_GROUPED2);
            
            int pause = 1;
        } catch(ParserException | IOException e) {
            Logger.getLogger(X509ParserTest.class.getName()).log(Level.SEVERE, null, e);
            throw e;
            
        } catch (KeyFileManagerException ex) {
            Logger.getLogger(X509ParserTest.class.getName()).log(Level.SEVERE, null, ex);
            throw ex;
        }
        
        
    }      
    
    
}
