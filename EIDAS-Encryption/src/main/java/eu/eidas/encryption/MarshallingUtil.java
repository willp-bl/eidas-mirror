package eu.eidas.encryption;

import eu.eidas.encryption.exception.MarshallException;
import eu.eidas.encryption.exception.UnmarshallException;

import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.encryption.EncryptedData;
import org.opensaml.xml.io.*;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.XMLConstants;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Map;

/**
 * Marshalling Util for the encryption
 * <p/>
 * Created by bodabel on 28/11/2014.
 */
class MarshallingUtil {

    private static final Logger LOGGER = LoggerFactory
            .getLogger(MarshallingUtil.class.getName());

    private MarshallingUtil(){
    }

    /**
     * Build the default set of parser features to use.
     * The default features set are:
     * <ul>
     * <li>{@link javax.xml.XMLConstants#FEATURE_SECURE_PROCESSING} = true</li>
     * <li>http://apache.org/xml/features/disallow-doctype-decl = true</li>
     * Reference : https://www.owasp.org/index.php/XML_External_Entity_%28XXE%29_Processing
     * </ul>
     */
    protected static  Map<String, Boolean> buildDefaultFeature(){
        Map<String, Boolean> features = new HashMap<String, Boolean>();
        features.put(XMLConstants.FEATURE_SECURE_PROCESSING, Boolean.TRUE);

        // Ignore the external DTD completely
        // Note: this is for Xerces only:
        features.put("http://apache.org/xml/features/nonvalidating/load-external-dtd", Boolean.FALSE);
        // This is the PRIMARY defense. If DTDs (doctypes) are disallowed, almost all XML entity attacks are prevented
        // Xerces 2 only - http://xerces.apache.org/xerces2-j/features.html#disallow-doctype-decl
        features.put("http://apache.org/xml/features/disallow-doctype-decl", Boolean.TRUE);

        // If you can't completely disable DTDs, then at least do the following:
        // Xerces 1 - http://xerces.apache.org/xerces-j/features.html#external-general-entities
        // Xerces 2 - http://xerces.apache.org/xerces2-j/features.html#external-general-entities
        features.put("http://xml.org/sax/features/external-general-entities", Boolean.FALSE);

        // Xerces 1 - http://xerces.apache.org/xerces-j/features.html#external-parameter-entities
        // Xerces 2 - http://xerces.apache.org/xerces2-j/features.html#external-parameter-entities
        features.put("http://xml.org/sax/features/external-parameter-entities", Boolean.FALSE);

        return features;
    }

    private static void initParserPool(BasicParserPool ppMgr){
        ppMgr.setBuilderFeatures(buildDefaultFeature());
        ppMgr.setNamespaceAware(true);
    }
    private static XMLObject performUnmarshall(final Element root) throws UnmarshallException, UnmarshallingException{
        // Get appropriate unmarshaller
        final UnmarshallerFactory unmarshallerFact = Configuration.getUnmarshallerFactory();
        // Unmarshall using the SAML Token root element
        if (unmarshallerFact != null && root != null) {
            final Unmarshaller unmarshaller = unmarshallerFact.getUnmarshaller(root);
            try {
                return unmarshaller.unmarshall(root);
            } catch (NullPointerException e) {
                LOGGER.info("Error element tag incomplet or null.", e.getMessage());
                throw new UnmarshallException("NullPointerException", e);
            }
        } else {
            LOGGER.info("Error element tag incomplet or null.");
            throw new UnmarshallException("NullPointerException : unmarshallerFact or root is null");
        }
    }
    /**
     * Method that unmarshalls a SAML Object from a byte array representation to
     * an XML Object.
     *
     * @param samlToken Byte array representation of a SAML Object
     * @return XML Object (superclass of SAMLObject)
     * @throws UnmarshallException
     */
    static XMLObject unmarshall(final byte[] samlToken)
            throws UnmarshallException {
        try {
            // Get parser pool manager
            final BasicParserPool ppMgr = new BasicParserPool();
            initParserPool(ppMgr);

            // Parse SAMLToken
            Document document = ppMgr.parse(new ByteArrayInputStream(samlToken));
            if (document != null) {
                final Element root = document.getDocumentElement();
                return performUnmarshall(root);
            } else {
                LOGGER.info("Error element tag incomplet or null.");
                throw new UnmarshallException("NullPointerException : document is null");
            }
        } catch (XMLParserException e) {
            LOGGER.info("XML Parsing Error.", e.getMessage());
            throw new UnmarshallException(e);
        } catch (UnmarshallingException e) {
            LOGGER.info("TransformerException.", e.getMessage());
            throw new UnmarshallException(e);
        }
    }


    /**
     * The Document Builder Factory.
     */
    private static javax.xml.parsers.DocumentBuilderFactory dbf = null;

    static {
        try {
            dbf = javax.xml.parsers.DocumentBuilderFactory.newInstance();
            dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            dbf.setNamespaceAware(true);
            dbf.setIgnoringComments(true);
        } catch (ParserConfigurationException e) {
            LOGGER.error("Error parser configuration.", e);
        }
    }

    private static void performMarshall(final XMLObject samlToken, Document doc)throws MarshallException{
        final MarshallerFactory marshallerFactory = Configuration
                .getMarshallerFactory();

        final Marshaller marshaller = marshallerFactory
                .getMarshaller(samlToken);
        try {
            marshaller.marshall(samlToken, doc);
        } catch (MarshallingException e) {
            throw new MarshallException(e);
        }


    }
    /**
     * Method that transform the received SAML object into a byte array
     * representation.
     *
     * @param samlToken the SAML token.
     * @return the byte[] of the SAML token.
     * @throws MarshallingException
     */
    static byte[] marshall(final XMLObject samlToken)
            throws MarshallException {

        if (dbf == null) {
            throw new MarshallException("Error parser configuration occurred! Check previous log entries for more details.");
        }

        try {
            javax.xml.parsers.DocumentBuilder docBuilder = dbf.newDocumentBuilder();

            final Document doc = docBuilder.newDocument();
            performMarshall(samlToken, doc);

            // Obtain a byte array representation of the marshalled SAML object
            String strXml=getXmlText(doc);
            LOGGER.trace("SAML request \n" + strXml);
            return strXml.getBytes("utf-8");

        } catch (ParserConfigurationException e) {
            LOGGER.error("ParserConfigurationException.", e.getMessage());
            throw new MarshallException(e);
        } catch (TransformerException e) {
            LOGGER.info("TransformerException.", e.getMessage());
            throw new MarshallException(e);
        } catch (UnsupportedEncodingException e) {
            LOGGER.info("UnsupportedEncodingException: utf-8", e.getMessage());
            throw new MarshallException(e);
        }
    }


    private static void performMarshall(final EncryptedData encryptedXML, Document doc) throws MarshallingException{
        final MarshallerFactory marshallerFactory = org.opensaml.Configuration
                .getMarshallerFactory();

        final Marshaller marshaller = marshallerFactory
                .getMarshaller(encryptedXML);

        marshaller.marshall(encryptedXML, doc);

    }
    private static String getXmlText(Document doc) throws TransformerException{
        final DOMSource domSource = new DOMSource(doc);
        final StringWriter writer = new StringWriter();
        final StreamResult result = new StreamResult(writer);
        final TransformerFactory transFactory = TransformerFactory.newInstance();
        Transformer transformer;

        transformer = transFactory.newTransformer();
        transformer.transform(domSource, result);
        return writer.toString();
    }
    static byte[] marshall(final EncryptedData encryptedXML)
            throws MarshallingException {

        if (dbf == null) {
            throw new MarshallingException("Error parser configuration occurred! Check previous log entries for more details.");
        }

        try {
            javax.xml.parsers.DocumentBuilder docBuilder = dbf.newDocumentBuilder();

            final Document doc = docBuilder.newDocument();
            performMarshall(encryptedXML ,doc);
            // Obtain a byte array representation of the marshalled SAML object
            String strXML=getXmlText(doc);
            LOGGER.debug("Encrypted XML \n" + strXML);
            return strXML.getBytes("utf-8");

        } catch (ParserConfigurationException e) {
            LOGGER.error("ParserConfigurationException.");
            throw new MarshallingException(e);
        } catch (TransformerException e) {
            LOGGER.error("TransformerException.");
            throw new MarshallingException(e);
        } catch (UnsupportedEncodingException e) {
            LOGGER.error("UnsupportedEncodingException:", e);
            throw new MarshallingException(e);
        }
    }

}
