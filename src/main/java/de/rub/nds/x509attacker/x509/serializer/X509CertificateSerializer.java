/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509.serializer;

import de.rub.nds.asn1tool.xmlparser.JaxbClassList;
import de.rub.nds.modifiablevariable.ModifiableVariable;
import de.rub.nds.modifiablevariable.ModificationFilter;
import de.rub.nds.modifiablevariable.VariableModification;
import de.rub.nds.x509attacker.x509.X509Certificate;
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
 * A helper class to serialize and deserialize X509Certificates.
 *
 */
public class X509CertificateSerializer {

    private static final Logger LOGGER = LogManager.getLogger(X509CertificateSerializer.class);

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
            classList.add(X509Certificate.class);

            Class[] jaxbClasses = classList.toArray(new Class[classList.size()]);
            for (Class someClass : jaxbClasses) {
                LOGGER.debug("Registering: " + someClass);
            }
            context = JAXBContext.newInstance(jaxbClasses);
        }
        return context;
    }

    /**
     * Writes a X509Certificate to a File
     *
     * @param  file
     *                               File to which the X509Certificate should be written
     * @param  cert
     *                               X509Certificate that should be written
     * @throws FileNotFoundException
     *                               Is thrown if the File cannot be found
     * @throws JAXBException
     *                               Is thrown when the Object cannot be serialized
     * @throws IOException
     *                               Is thrown if the Process doesn't have the rights to write to the File
     */
    public static void write(File file, X509Certificate cert) throws FileNotFoundException, JAXBException, IOException {
        if (!file.exists()) {
            file.createNewFile();
        }
        FileOutputStream fos = new FileOutputStream(file);
        X509CertificateSerializer.write(fos, cert);
    }

    /**
     * Writes a X509Certificate to an Outputstream
     *
     * @param  outputStream
     *                       Outputstream to write to
     * @param  cert
     *                       X509Certificate to serializ
     * @throws JAXBException
     *                       If something goes wrong
     * @throws IOException
     *                       If something goes wrong
     */
    public static void write(OutputStream outputStream, X509Certificate cert) throws JAXBException, IOException {
        context = getJAXBContext();
        Marshaller m = context.createMarshaller();
        m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        m.marshal(cert, outputStream);
        outputStream.close();
    }

    /**
     * Reads a X509Certificate from an InputStream
     *
     * @param  inputStream
     *                            Inputstream to read from
     * @return                    Read X509Certificate
     * @throws JAXBException
     *                            If something goes wrong
     * @throws IOException
     *                            If something goes wrong
     * @throws XMLStreamException
     *                            If something goes wrong
     */
    public static X509Certificate read(InputStream inputStream) throws JAXBException, IOException, XMLStreamException {
        context = getJAXBContext();
        Unmarshaller m = context.createUnmarshaller();
        XMLInputFactory xif = XMLInputFactory.newFactory();
        xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader xsr = xif.createXMLStreamReader(inputStream);
        X509Certificate cert = (X509Certificate) m.unmarshal(xsr);
        inputStream.close();
        return cert;
    }

    /**
     * Returns a somehow deep copy of the X509Certificate. The WorkflowTrace is deep copied and the rest is passed as a
     * reference.
     *
     * @param  cert
     *                                             X509Certificate to copy
     * @return
     * @throws jakarta.xml.bind.JAXBException
     * @throws java.io.IOException
     * @throws javax.xml.stream.XMLStreamException
     */
    public static X509Certificate copyX509Certificate(X509Certificate cert)
        throws JAXBException, IOException, XMLStreamException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        X509CertificateSerializer.write(stream, cert);
        stream.flush();
        X509Certificate copiedCert = X509CertificateSerializer.read(new ByteArrayInputStream(stream.toByteArray()));
        return copiedCert;
    }

    private X509CertificateSerializer() {
    }

}
