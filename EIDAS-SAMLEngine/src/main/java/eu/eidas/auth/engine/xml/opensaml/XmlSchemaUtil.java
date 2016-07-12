package eu.eidas.auth.engine.xml.opensaml;

import java.io.IOException;

import javax.annotation.Nonnull;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.dom.DOMSource;
import javax.xml.validation.Schema;
import javax.xml.validation.Validator;

import org.opensaml.common.xml.SAMLSchemaBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import eu.eidas.auth.commons.EidasErrorKey;
import eu.eidas.auth.commons.EidasErrors;
import eu.eidas.auth.commons.xml.DocumentBuilderFactoryUtil;
import eu.eidas.auth.engine.AbstractProtocolEngine;
import eu.eidas.engine.exceptions.EIDASSAMLEngineException;

/**
 * XML Schema Utility class.
 *
 * @since 1.1
 */
public final class XmlSchemaUtil {

    private static final Logger LOG = LoggerFactory.getLogger(XmlSchemaUtil.class);

    public static Document validateSamlSchema(@Nonnull String samlString) throws EIDASSAMLEngineException {
        try {
            return validateSchema(SAMLSchemaBuilder.getSAML11Schema(), samlString);
        } catch (SAXException e) {
            LOG.error(AbstractProtocolEngine.SAML_EXCHANGE, "BUSINESS EXCEPTION : Validate schema exception: " + e, e);
            throw new EIDASSAMLEngineException(EidasErrors.get(EidasErrorKey.MESSAGE_VALIDATION_ERROR.errorCode()),
                                               EidasErrorKey.MESSAGE_VALIDATION_ERROR.errorMessage(), e);
        }
    }

    public static Document validateSamlSchema(@Nonnull byte[] samlBytes) throws EIDASSAMLEngineException {
        try {
            return validateSchema(SAMLSchemaBuilder.getSAML11Schema(), samlBytes);
        } catch (SAXException e) {
            LOG.error(AbstractProtocolEngine.SAML_EXCHANGE, "BUSINESS EXCEPTION : Validate schema exception: " + e, e);
            throw new EIDASSAMLEngineException(EidasErrors.get(EidasErrorKey.MESSAGE_VALIDATION_ERROR.errorCode()),
                                               EidasErrorKey.MESSAGE_VALIDATION_ERROR.errorMessage(), e);
        }
    }

    public static void validateSchema(@Nonnull Schema schema, @Nonnull Document document)
            throws EIDASSAMLEngineException {
        try {
            Element element = document.getDocumentElement();
            Validator validator = schema.newValidator();
            DOMSource domSrc = new DOMSource(element);
            validator.validate(domSrc);
        } catch (IOException | SAXException e) {
            LOG.error(AbstractProtocolEngine.SAML_EXCHANGE, "BUSINESS EXCEPTION : Validate schema exception: " + e, e);
            throw new EIDASSAMLEngineException(EidasErrors.get(EidasErrorKey.MESSAGE_VALIDATION_ERROR.errorCode()),
                                               EidasErrorKey.MESSAGE_VALIDATION_ERROR.errorMessage(), e);
        }
    }

    public static Document validateSchema(@Nonnull Schema schema, @Nonnull String xmlString)
            throws EIDASSAMLEngineException {
        Document document;
        try {
            document = DocumentBuilderFactoryUtil.parse(xmlString);
        } catch (IOException | SAXException | ParserConfigurationException e) {
            LOG.error(AbstractProtocolEngine.SAML_EXCHANGE, "BUSINESS EXCEPTION : Validate schema exception: " + e, e);
            throw new EIDASSAMLEngineException(EidasErrors.get(EidasErrorKey.MESSAGE_VALIDATION_ERROR.errorCode()),
                                               EidasErrorKey.MESSAGE_VALIDATION_ERROR.errorMessage(), e);
        }
        validateSchema(schema, document);
        return document;
    }

    public static Document validateSchema(@Nonnull Schema schema, @Nonnull byte[] xmlBytes)
            throws EIDASSAMLEngineException {
        Document document;
        try {
            document = DocumentBuilderFactoryUtil.parse(xmlBytes);
        } catch (IOException | SAXException | ParserConfigurationException e) {
            LOG.error(AbstractProtocolEngine.SAML_EXCHANGE, "BUSINESS EXCEPTION : Validate schema exception: " + e, e);
            throw new EIDASSAMLEngineException(EidasErrors.get(EidasErrorKey.MESSAGE_VALIDATION_ERROR.errorCode()),
                                               EidasErrorKey.MESSAGE_VALIDATION_ERROR.errorMessage(), e);
        }
        validateSchema(schema, document);
        return document;
    }

    private XmlSchemaUtil() {
    }
}
