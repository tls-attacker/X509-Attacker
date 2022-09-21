/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509.serializer;

import de.rub.nds.asn1.translator.AlgorithmIdentifierContext;
import de.rub.nds.asn1.translator.AttributeTypeAndValueContext;
import de.rub.nds.asn1.translator.AuthorityKeyIdentifierContext;
import de.rub.nds.asn1.translator.CertificateContext;
import de.rub.nds.asn1.translator.CertificateOuterContext;
import de.rub.nds.asn1.translator.ExplicitExtensionsContext;
import de.rub.nds.asn1.translator.ExplicitVersionContext;
import de.rub.nds.asn1.translator.ExtAuthorityKeyIdentifierContext;
import de.rub.nds.asn1.translator.ExtKeyUsageContext;
import de.rub.nds.asn1.translator.ExtensionContext;
import de.rub.nds.asn1.translator.ExtensionsContext;
import de.rub.nds.asn1.translator.NameContext;
import de.rub.nds.asn1.translator.ParseNativeTypesContext;
import de.rub.nds.asn1.translator.RelativeDistinguishedNameContext;
import de.rub.nds.asn1.translator.SubjectPublicKeyInfoContext;
import de.rub.nds.asn1.translator.TBSCertificateContext;
import de.rub.nds.asn1.translator.TestExtensionsContext;
import de.rub.nds.asn1.translator.ValidityContext;
import de.rub.nds.asn1tool.xmlparser.JaxbClassList;
import de.rub.nds.modifiablevariable.ModifiableVariable;
import de.rub.nds.modifiablevariable.ModificationFilter;
import de.rub.nds.modifiablevariable.VariableModification;
import de.rub.nds.x509attacker.x509.X509CertificateChain;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Marshaller;
import jakarta.xml.bind.Unmarshaller;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A helper class to serialize and deserialize X509CertificateChains.
 *
 */
public class X509CertificateChainSerializer {

    private static final Logger LOGGER = LogManager.getLogger(X509CertificateChainSerializer.class);

    /**
     * context initialization is expensive, we need to do that only once
     */
    private static JAXBContext context;

    /**
     * Returns an initialized JaxbContext
     *
     * @return
     * @throws JAXBException
     * @throws IOException
     */
    private static synchronized JAXBContext getJAXBContext() throws JAXBException, IOException {
        if (context == null) {

            Class[] X509AttackerClasses = JaxbClassList.getInstance().getClasses();
            List<Class> classList = new ArrayList<>(Arrays.asList(X509AttackerClasses));
            classList.add(ModificationFilter.class);
            classList.add(VariableModification.class);
            classList.add(ModifiableVariable.class);
            classList.add(File.class);
            classList.add(ParseNativeTypesContext.class);
            classList.add(AlgorithmIdentifierContext.class);
            classList.add(AttributeTypeAndValueContext.class);
            classList.add(CertificateContext.class);
            classList.add(CertificateOuterContext.class);
            classList.add(ExplicitExtensionsContext.class);
            classList.add(ExtensionContext.class);
            classList.add(ExtensionsContext.class);
            classList.add(NameContext.class);
            classList.add(RelativeDistinguishedNameContext.class);
            classList.add(SubjectPublicKeyInfoContext.class);
            classList.add(TBSCertificateContext.class);
            classList.add(ValidityContext.class);
            classList.add(ExplicitVersionContext.class);
            classList.add(ExtKeyUsageContext.class);
            classList.add(ExtAuthorityKeyIdentifierContext.class);
            classList.add(AuthorityKeyIdentifierContext.class);
            classList.add(X509CertificateChain.class);
            Class[] jaxbClasses = classList.toArray(new Class[classList.size()]);

            context = JAXBContext.newInstance(jaxbClasses);
        }
        return context;
    }

    /**
     * Writes a X509CertificateChain to a File
     *
     * @param  file
     *                               File to which the X509CertificateChain should be written
     * @param  chain
     *                               X509CertificateChain that should be written
     * @throws FileNotFoundException
     *                               Is thrown if the File cannot be found
     * @throws JAXBException
     *                               Is thrown when the Object cannot be serialized
     * @throws IOException
     *                               Is thrown if the Process doesn't have the rights to write to the File
     */
    public static void write(File file, X509CertificateChain chain)
        throws FileNotFoundException, JAXBException, IOException {
        if (!file.exists()) {
            file.createNewFile();
        }
        FileOutputStream fos = new FileOutputStream(file);
        X509CertificateChainSerializer.write(fos, chain);
    }

    /**
     * Writes a X509CertificateChain to an Outputstream
     *
     * @param  outputStream
     *                       Outputstream to write to
     * @param  chain
     *                       X509CertificateChain to serializ
     * @throws JAXBException
     *                       If something goes wrong
     * @throws IOException
     *                       If something goes wrong
     */
    public static void write(OutputStream outputStream, X509CertificateChain chain) throws JAXBException, IOException {
        context = getJAXBContext();
        Marshaller m = context.createMarshaller();
        m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        m.marshal(chain, outputStream);
        outputStream.close();
    }

    /**
     * Reads a X509CertificateChain from an InputStream
     *
     * @param  inputStream
     *                            Inputstream to read from
     * @return                    Read X509CertificateChain
     * @throws JAXBException
     *                            If something goes wrong
     * @throws IOException
     *                            If something goes wrong
     * @throws XMLStreamException
     *                            If something goes wrong
     */
    public static X509CertificateChain read(InputStream inputStream)
        throws JAXBException, IOException, XMLStreamException {
        context = getJAXBContext();
        Unmarshaller m = context.createUnmarshaller();
        XMLInputFactory xif = XMLInputFactory.newFactory();
        xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader xsr = xif.createXMLStreamReader(inputStream);
        X509CertificateChain chain = (X509CertificateChain) m.unmarshal(xsr);
        inputStream.close();
        return chain;
    }

    /**
     * Returns a somehow deep copy of the X509CertificateChain. The WorkflowTrace is deep copied and the rest is passed
     * as a reference.
     *
     * @param  chain
     *                                             X509CertificateChain to copy
     * @return
     * @throws jakarta.xml.bind.JAXBException
     * @throws java.io.IOException
     * @throws javax.xml.stream.XMLStreamException
     */
    public static X509CertificateChain copyX509CertificateChain(X509CertificateChain chain)
        throws JAXBException, IOException, XMLStreamException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        X509CertificateChainSerializer.write(stream, chain);
        stream.flush();
        X509CertificateChain copiedChain =
            X509CertificateChainSerializer.read(new ByteArrayInputStream(stream.toByteArray()));
        return copiedChain;
    }

    private X509CertificateChainSerializer() {
    }

}
