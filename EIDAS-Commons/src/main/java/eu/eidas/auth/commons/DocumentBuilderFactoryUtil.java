package eu.eidas.auth.commons;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

/**
 * Utility class used to create the document builder factory with a sufficient level of security
 * See https://www.owasp.org/index.php/XML_Entity_(XXE)_Processing for more details
 */
public final class DocumentBuilderFactoryUtil {
    private DocumentBuilderFactoryUtil(){

    }
    public static DocumentBuilderFactory getSecureDocumentBuilderFactory() throws ParserConfigurationException{
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        documentBuilderFactory.setNamespaceAware(true);
        documentBuilderFactory.setIgnoringComments(true);
        // This is the PRIMARY defense. If DTDs (doctypes) are disallowed, almost all XML entity attacks are prevented
        // Xerces 2 only - http://xerces.apache.org/xerces2-j/features.html#disallow-doctype-decl
        String feature = "http://apache.org/xml/features/disallow-doctype-decl";
        documentBuilderFactory.setFeature(feature, true);

        // If you can't completely disable DTDs, then at least do the following:
        // Xerces 1 - http://xerces.apache.org/xerces-j/features.html#external-general-entities
        // Xerces 2 - http://xerces.apache.org/xerces2-j/features.html#external-general-entities
        feature = "http://xml.org/sax/features/external-general-entities";
        documentBuilderFactory.setFeature(feature, false);

        // Xerces 1 - http://xerces.apache.org/xerces-j/features.html#external-parameter-entities
        // Xerces 2 - http://xerces.apache.org/xerces2-j/features.html#external-parameter-entities
        feature = "http://xml.org/sax/features/external-parameter-entities";
        documentBuilderFactory.setFeature(feature, false);

        // and these as well, per Timothy Morgan's 2014 paper: "XML Schema, DTD, and Entity Attacks" (see reference below)
        documentBuilderFactory.setXIncludeAware(false);
        documentBuilderFactory.setExpandEntityReferences(false);
        return documentBuilderFactory;
    }

}
