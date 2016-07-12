package eu.eidas.auth.engine.core.stork;

import eu.eidas.auth.commons.*;
import eu.eidas.auth.engine.AbstractSAMLEngine;
import eu.eidas.auth.engine.SAMLEngineUtils;
import eu.eidas.auth.engine.EIDASSAMLEngine;
import eu.eidas.auth.engine.core.AbstractExtensionProcessor;
import eu.eidas.auth.engine.core.ExtensionProcessorI;
import eu.eidas.auth.engine.core.SAMLExtensionFormat;
import eu.eidas.auth.engine.core.validator.STORKAttributes;
import eu.eidas.auth.engine.core.validator.eidas.EIDASAttributes;
import eu.eidas.engine.exceptions.EIDASSAMLEngineException;
import eu.eidas.engine.exceptions.EIDASSAMLEngineRuntimeException;

import org.apache.commons.lang.StringUtils;
import org.opensaml.saml2.common.Extensions;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.impl.XSAnyImpl;
import org.opensaml.xml.schema.impl.XSStringImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import java.io.*;
import java.util.*;

public class StorkExtensionProcessor extends AbstractExtensionProcessor implements ExtensionProcessorI{
    /** The Constant LOG. */
    private static final Logger LOG = LoggerFactory.getLogger(StorkExtensionProcessor.class.getName());
    private static final String STORK_REQUEST_VALIDATOR_SUITE_ID = "storkRequestValidatorSuiteId";
    public String getRequestValidatorId(){
        return STORK_REQUEST_VALIDATOR_SUITE_ID;
    }

    private static final String STORK_RESPONSE_VALIDATOR_SUITE_ID = "storkResponseValidatorSuiteId";
    public String getResponseValidatorId(){
        return STORK_RESPONSE_VALIDATOR_SUITE_ID;
    }
    /**
     * Process all elements XMLObjects from the extensions.
     *
     * @param extensions the extensions from the authentication request.
     *
     * @return the STORK authentication request
     *
     * @throws EIDASSAMLEngineException the STORKSAML engine exception
     */
    public EIDASAuthnRequest processExtensions(final Extensions extensions)
            throws EIDASSAMLEngineException {
        LOG.debug("Process the extensions for Stork 1.0");

        final EIDASAuthnRequest request = new EIDASAuthnRequest();

        final QAAAttribute qaa = (QAAAttribute) extensions
                .getUnknownXMLObjects(QAAAttribute.DEF_ELEMENT_NAME).get(0);
        request.setQaa(Integer.parseInt(qaa.getQaaLevel()));

        fillRequestSPSector(request, extensions);

        fillRequestSPApplication(request, extensions);

        fillRequestSPCountry(request, extensions);

        fillRequestEIDCrossBorderShare(request, extensions);

        fillRequestEIDCrossSectorShare(request, extensions);

        fillRequestEIDSectorShare(request, extensions);

        fillAuthAttributes(request, extensions);

        final RequestedAttributes requestedAttr = (RequestedAttributes) extensions
                .getUnknownXMLObjects(RequestedAttributes.DEF_ELEMENT_NAME)
                .get(0);

        final List<RequestedAttribute> reqAttrs = requestedAttr.getAttributes();

        final IPersonalAttributeList personalAttrList = new PersonalAttributeList();

        String attributeName;
        for (int nextAttribute = 0; nextAttribute < reqAttrs.size(); nextAttribute++) {
            final RequestedAttribute attribute = reqAttrs.get(nextAttribute);
            final PersonalAttribute personalAttribute = new PersonalAttribute();
            personalAttribute.setIsRequired(Boolean.valueOf(attribute.isRequired()));
            personalAttribute.setFriendlyName(attribute.getFriendlyName());
            attributeName = attribute.getName();

            // recover the last name from the string.
            personalAttribute.setName(attributeName.substring(attributeName
                    .lastIndexOf('/') + 1));

            final List<String> valores = new ArrayList<String>();
            final List<XMLObject> values = attribute.getOrderedChildren();

            for (int nextSimpleValue = 0; nextSimpleValue < values.size(); nextSimpleValue++) {

                // Process attributes simples. An AuthenticationRequest only
                // must contains simple values.

                final XMLObject xmlObject = values.get(nextSimpleValue);

                if(xmlObject instanceof XSStringImpl){

                    final XSStringImpl xmlString = (XSStringImpl) values.get(nextSimpleValue);
                    valores.add(xmlString.getValue());

                }else{

                    if ("http://www.stork.gov.eu/1.0/signedDoc".equals(attributeName)) {

                        valores.add(extractEDocValue((XSAnyImpl) values.get(nextSimpleValue)));

                    }else{

                        final XSAnyImpl xmlString = (XSAnyImpl) values.get(nextSimpleValue);
                        valores.add(xmlString.getTextContent());
                    }



                }
            }
            personalAttribute.setValue(valores);
            personalAttrList.add(personalAttribute);
        }

        request.setPersonalAttributeList(personalAttrList);

        return request;
    }

    private static void fillRequestSPSector(EIDASAuthnRequest request,final Extensions extensions){
        List optionalElements = extensions.getUnknownXMLObjects(SPSector.DEF_ELEMENT_NAME);

        if (!optionalElements.isEmpty()) {
            final SPSector sector = (SPSector) extensions.getUnknownXMLObjects(
                    SPSector.DEF_ELEMENT_NAME).get(0);
            request.setSpSector(sector.getSPSector());
        }
    }
    private static void fillRequestSPApplication(EIDASAuthnRequest request,final Extensions extensions){
        List optionalElements = extensions.getUnknownXMLObjects(SPApplication.DEF_ELEMENT_NAME);

        if (!optionalElements.isEmpty()) {
            final SPApplication application = (SPApplication) extensions
                    .getUnknownXMLObjects(SPApplication.DEF_ELEMENT_NAME).get(0);
            request.setSpApplication(application.getSPApplication());
        }
    }
    private static void fillRequestSPCountry(EIDASAuthnRequest request,final Extensions extensions){
        List optionalElements = extensions.getUnknownXMLObjects(SPCountry.DEF_ELEMENT_NAME);

        if (!optionalElements.isEmpty()) {
            final SPCountry application = (SPCountry) extensions
                    .getUnknownXMLObjects(SPCountry.DEF_ELEMENT_NAME).get(0);
            request.setSpCountry(application.getSPCountry());
        }
    }
    private static void fillRequestEIDCrossBorderShare(EIDASAuthnRequest request,final Extensions extensions){
        List listCrossBorderShare = extensions
                .getUnknownXMLObjects(EIDCrossBorderShare.DEF_ELEMENT_NAME);

        if (!listCrossBorderShare .isEmpty()) {
            final EIDCrossBorderShare crossBorderShare = (EIDCrossBorderShare) listCrossBorderShare.get(0);
            request.setEIDCrossBorderShare(Boolean.parseBoolean(crossBorderShare
                    .getEIDCrossBorderShare()));
        }
    }
    private static void fillRequestEIDCrossSectorShare(EIDASAuthnRequest request,final Extensions extensions){
        List listCrosSectorShare = extensions.getUnknownXMLObjects(EIDCrossSectorShare.DEF_ELEMENT_NAME);

        if (!listCrosSectorShare.isEmpty()) {
            final EIDCrossSectorShare crossSectorShare = (EIDCrossSectorShare) listCrosSectorShare.get(0);
            request.setEIDCrossSectorShare(Boolean.parseBoolean(crossSectorShare
                    .getEIDCrossSectorShare()));
        }
    }
    private static void fillRequestEIDSectorShare(EIDASAuthnRequest request,final Extensions extensions){
        List listSectorShareExtension = extensions.getUnknownXMLObjects(EIDSectorShare.DEF_ELEMENT_NAME);
        if (!listSectorShareExtension.isEmpty()) {
            final EIDSectorShare sectorShare = (EIDSectorShare) listSectorShareExtension.get(0);
            request.setEIDSectorShare(Boolean.parseBoolean(sectorShare.getEIDSectorShare()));
        }
    }

    private static String computeCitizenCode(List<XMLObject> authAttrs){
        CitizenCountryCode citizenCountryCodeElement = null;
        final AuthenticationAttributes authnAttr = (AuthenticationAttributes) authAttrs.get(0);
        VIDPAuthenticationAttributes vidpAuthnAttr = authnAttr==null?null:authnAttr.getVIDPAuthenticationAttributes();
        if (vidpAuthnAttr != null){
            citizenCountryCodeElement = vidpAuthnAttr.getCitizenCountryCode();
        }

        String citizenCountryCode = null;
        if(citizenCountryCodeElement!=null){
            citizenCountryCode = citizenCountryCodeElement.getCitizenCountryCode();
        }
        return citizenCountryCode;

    }
    private static String computeSpID(List<XMLObject> authAttrs){
        final AuthenticationAttributes authnAttr = (AuthenticationAttributes) authAttrs.get(0);
        VIDPAuthenticationAttributes vidpAuthnAttr = authnAttr==null?null:authnAttr.getVIDPAuthenticationAttributes();
        SPInformation spInformation = vidpAuthnAttr==null?null:vidpAuthnAttr.getSPInformation();
        SPID spidElement = null;
        if (spInformation != null){
            spidElement = spInformation.getSPID();
        }

        String spid = null;
        if(spidElement!=null){
            spid = spidElement.getSPID();
        }
        return spid;
    }
    private static void fillAuthAttributes(EIDASAuthnRequest request,final Extensions extensions)throws EIDASSAMLEngineException{
        List<XMLObject> authAttrs = extensions.getUnknownXMLObjects(AuthenticationAttributes.DEF_ELEMENT_NAME);

        if (authAttrs != null && !authAttrs.isEmpty()) {


            String citizenCountryCode=computeCitizenCode(authAttrs);

            if(citizenCountryCode!= null && StringUtils.isNotBlank(citizenCountryCode)){
                request.setCitizenCountryCode(citizenCountryCode);
            }

            String spid=computeSpID(authAttrs);
            if (spid != null && StringUtils.isNotBlank(spid)) {
                request.setSPID(spid);
            }
        }

        if (extensions.getUnknownXMLObjects(RequestedAttributes.DEF_ELEMENT_NAME) == null) {
            LOG.info(AbstractSAMLEngine.SAML_EXCHANGE, "BUSINESS EXCEPTION : Extensions not contains any requested attribute.");
            throw new EIDASSAMLEngineException(EIDASErrors.INTERNAL_ERROR.errorCode(),
                    EIDASErrors.INTERNAL_ERROR.errorCode(),"Extensions not contains any requested attribute.");
        }
    }
    private static String extractEDocValue(final XSAnyImpl xmlString){
        TransformerFactory transFactory = TransformerFactory.newInstance();
        Transformer transformer = null;
        try {
            transformer = transFactory.newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        } catch (TransformerConfigurationException e) {
            LOG.warn(AbstractSAMLEngine.SAML_EXCHANGE, "Error transformer configuration exception", e.getMessage());
            LOG.debug(AbstractSAMLEngine.SAML_EXCHANGE, "Error transformer configuration exception", e);
        }
        StringWriter buffer = new StringWriter();
        try {
            if (transformer!=null && xmlString != null && xmlString.getUnknownXMLObjects() != null && !xmlString.getUnknownXMLObjects().isEmpty() ){
                transformer.transform(new DOMSource(xmlString.getUnknownXMLObjects().get(0).getDOM()),
                        new StreamResult(buffer));
            }
        } catch (TransformerException e) {
            LOG.info(AbstractSAMLEngine.SAML_EXCHANGE, "BUSINESS EXCEPTION : Error transformer exception", e.getMessage());
            LOG.debug(AbstractSAMLEngine.SAML_EXCHANGE, "BUSINESS EXCEPTION : Error transformer exception", e);
        }
        return buffer.toString();

    }
    StorkExtensionConfiguration configuration=new StorkExtensionConfiguration();
    /**
     * Generate stork extensions.
     *
     * @param request the request
     *
     * @return the extensions
     *
     * @throws EIDASSAMLEngineException the STORKSAML engine exception
     */
    public Extensions generateExtensions(final EIDASSAMLEngine engine, final EIDASAuthnRequest request)
            throws EIDASSAMLEngineException {
        LOG.trace("Generate STORKExtensions");

        final Extensions extensions = SAMLEngineUtils.generateExtension();

        LOG.trace("Generate QAAAttribute");
        final QAAAttribute qaaAttribute = generateQAAAttribute(request.getQaa());
        extensions.getUnknownXMLObjects().add(qaaAttribute);

        addExtensionSpSector(request, extensions);

        addExtensionSPInstitution(request, extensions);

        addExtensionSpApplication(request, extensions);
        addExtensionSpCountry(request, extensions);

        //eIDSectorShare: optional; default value: false.
        String valueSectorShare = engine.getSamlCoreProperties()
                .iseIDSectorShare();

        if (StringUtils.isNotEmpty(valueSectorShare)) {
            // Add information about the use of the SAML message.
            LOG.trace("Generate EIDSectorShare");
            final EIDSectorShare eIdSectorShare = (EIDSectorShare) SAMLEngineUtils
                    .createSamlObject(EIDSectorShare.DEF_ELEMENT_NAME);

            eIdSectorShare.setEIDSectorShare(String.valueOf(Boolean.valueOf(valueSectorShare)));

            extensions.getUnknownXMLObjects().add(eIdSectorShare);
        }

        String valueCrossSectorShare = engine.getSamlCoreProperties()
                .iseIDCrossSectorShare();

        if (StringUtils.isNotEmpty(valueCrossSectorShare)) {
            LOG.trace("Generate EIDCrossSectorShare");
            final EIDCrossSectorShare eIdCrossSecShare = (EIDCrossSectorShare) SAMLEngineUtils
                    .createSamlObject(EIDCrossSectorShare.DEF_ELEMENT_NAME);
            eIdCrossSecShare.setEIDCrossSectorShare(String.valueOf(Boolean.valueOf(valueCrossSectorShare)));
            extensions.getUnknownXMLObjects().add(eIdCrossSecShare);
        }


        String valueCrossBorderShare = engine.getSamlCoreProperties()
                .iseIDCrossBorderShare();

        if (StringUtils.isNotEmpty(valueCrossBorderShare)) {
            LOG.trace("Generate EIDCrossBorderShare");
            final EIDCrossBorderShare eIdCrossBordShare = (EIDCrossBorderShare) SAMLEngineUtils
                    .createSamlObject(EIDCrossBorderShare.DEF_ELEMENT_NAME);
            eIdCrossBordShare.setEIDCrossBorderShare(String.valueOf(Boolean.valueOf(valueCrossBorderShare)));
            extensions.getUnknownXMLObjects().add(eIdCrossBordShare);
        }


        // Add information about requested attributes.
        LOG.trace("Generate RequestedAttributes.");
        final RequestedAttributes reqAttributes = (RequestedAttributes) SAMLEngineUtils
                .createSamlObject(RequestedAttributes.DEF_ELEMENT_NAME);

        fillRequestedAttributes(engine, request, reqAttributes);
        // Add requested attributes.
        extensions.getUnknownXMLObjects().add(reqAttributes);

        CitizenCountryCode citizenCountryCode = null;
        if (request.getCitizenCountryCode() != null && StringUtils.isNotBlank(request.getCitizenCountryCode())){
            LOG.trace("Generate CitizenCountryCode");
            citizenCountryCode = (CitizenCountryCode) SAMLEngineUtils
                    .createSamlObject(CitizenCountryCode.DEF_ELEMENT_NAME);

            citizenCountryCode.setCitizenCountryCode(request
                    .getCitizenCountryCode().toUpperCase());
        }

        SPID spid = null;
        if(request.getSPID()!=null && StringUtils.isNotBlank(request.getSPID())) {
            LOG.trace("Generate SPID");
            spid = (SPID) SAMLEngineUtils
                    .createSamlObject(SPID.DEF_ELEMENT_NAME);

            spid.setSPID(request.getSPID().toUpperCase());
        }

        AuthenticationAttributes authenticationAttr = (AuthenticationAttributes) SAMLEngineUtils.createSamlObject(AuthenticationAttributes.DEF_ELEMENT_NAME);
        // Regarding the specs & xsd, the SPID can be absent
        if (spid != null) {
            final VIDPAuthenticationAttributes vIDPauthenticationAttr = (VIDPAuthenticationAttributes) SAMLEngineUtils.createSamlObject(VIDPAuthenticationAttributes.DEF_ELEMENT_NAME);

            final SPInformation spInformation = (SPInformation) SAMLEngineUtils.createSamlObject(SPInformation.DEF_ELEMENT_NAME);

            if (citizenCountryCode != null) {
                vIDPauthenticationAttr.setCitizenCountryCode(citizenCountryCode);
            }

            spInformation.setSPID(spid);

            vIDPauthenticationAttr.setSPInformation(spInformation);

            authenticationAttr.setVIDPAuthenticationAttributes(vIDPauthenticationAttr);
        }
        extensions.getUnknownXMLObjects().add(authenticationAttr);


        return extensions;

    }
    /**
     * Generate the quality authentication assurance level.
     *
     * @param qaal the level of quality authentication assurance.
     *
     * @return the quality authentication assurance attribute
     *
     * @throws EIDASSAMLEngineException the STORKSAML engine exception
     */
    public static QAAAttribute generateQAAAttribute(final int qaal)
            throws EIDASSAMLEngineException {
        LOG.debug("Generate QAAAttribute.");
        XMLObject obj = SAMLEngineUtils.createSamlObject(QAAAttribute.DEF_ELEMENT_NAME);
        final QAAAttribute qaaAttribute = (QAAAttribute)obj ;
        qaaAttribute.setQaaLevel(String.valueOf(qaal));
        return qaaAttribute;
    }

    private static void addExtensionSpSector(final EIDASAuthnRequest request, Extensions extensions)throws EIDASSAMLEngineException{
        if (StringUtils.isNotEmpty(request
                .getSpSector())) {
            // Add information about service provider.
            LOG.trace("Generate SPSector");
            final SPSector sector = SAMLEngineUtils.generateSPSector(request
                    .getSpSector());
            extensions.getUnknownXMLObjects().add(sector);
        }

    }
    private static void addExtensionSPInstitution(final EIDASAuthnRequest request, Extensions extensions)throws EIDASSAMLEngineException{
        //Delete from specification. Kept for compatibility with Provider Name value
        LOG.trace("Generate SPInstitution");
        final SPInstitution institution = SAMLEngineUtils
                .generateSPInstitution(request.getProviderName());
        extensions.getUnknownXMLObjects().add(institution);
    }
    private static void addExtensionSpApplication(final EIDASAuthnRequest request, Extensions extensions)throws EIDASSAMLEngineException{
        if (StringUtils.isNotEmpty(request.getSpApplication())) {
            LOG.trace("Generate SPApplication");
            final SPApplication application = SAMLEngineUtils
                    .generateSPApplication(request.getSpApplication());
            extensions.getUnknownXMLObjects().add(application);
        }
    }
    private static void addExtensionSpCountry(final EIDASAuthnRequest request, Extensions extensions)throws EIDASSAMLEngineException{
        if (StringUtils.isNotEmpty(request.getSpCountry())) {
            LOG.trace("Generate SPCountry");
            final SPCountry country = SAMLEngineUtils.generateSPCountry(request
                    .getSpCountry());
            extensions.getUnknownXMLObjects().add(country);
        }
    }
    private static void fillRequestedAttributes(final EIDASSAMLEngine engine, final EIDASAuthnRequest request,RequestedAttributes reqAttributes)
            throws EIDASSAMLEngineException{
        LOG.trace("SAML Engine configuration properties load.");
        final Iterator<PersonalAttribute> iterator = request
                .getPersonalAttributeList().iterator();

        while (iterator.hasNext()) {

            final PersonalAttribute attribute = iterator.next();

            if (attribute == null || StringUtils.isBlank(attribute.getName())) {
                LOG.info(EIDASSAMLEngine.SAML_EXCHANGE, EIDASSAMLEngine.ATTRIBUTE_EMPTY_LITERAL);
                throw new EIDASSAMLEngineException(EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                        EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),EIDASSAMLEngine.ATTRIBUTE_EMPTY_LITERAL);
            }

            // Verified if exits the attribute name.
            final String attributeName = engine.getSamlCoreProperties()
                    .getProperty(attribute.getName());

            if (StringUtils.isBlank(attributeName)) {
                LOG.trace("Attribute name: {} was not found.", attribute
                        .getName());
                throw new EIDASSAMLEngineException(EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                        EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"Attribute name: " + attribute.getName() + " was not found.");
            }

            // Friendly name it's an optional attribute.
            String friendlyName = null;

            if (engine.getSamlCoreProperties().isFriendlyName()) {
                friendlyName = attribute.getName();
            }


            String isRequired = null;
            if (engine.getSamlCoreProperties().isRequired()) {
                isRequired = String.valueOf(attribute.isRequired());
            }


            LOG.trace("Generate requested attribute: " + attributeName);
            final RequestedAttribute requestedAttr = SAMLEngineUtils
                    .generateReqAuthnAttributeSimple(engine, attributeName,
                            friendlyName, isRequired, attribute.getValue());

            // Add requested attribute.
            reqAttributes.getAttributes().add(requestedAttr);
        }

    }

    public String namePrefix(){
        return "";
    }
    public SAMLExtensionFormat getFormat(){
        return SAMLExtensionFormat.STORK10;
    }

    @Override
    public void configureExtension() {
        configuration.configureExtension();
    }

    @Override
    public Set<String> getSupportedAttributes(){
        //not supported for stork
        return new HashSet<String>();
    }
    @Override
    public boolean isValidRequest(AuthnRequest request){
        return true;
    }
    public Attribute generateAttrSimple(final String name,
                                         final String status, final List<String> values,
                                         final boolean isHashing) throws EIDASSAMLEngineException {
        LOG.trace("Generate attribute simple: {}", name);
        final Attribute attribute = (Attribute) SAMLEngineUtils
                .createSamlObject(Attribute.DEFAULT_ELEMENT_NAME);

        attribute.setName(name);
        attribute.setNameFormat(Attribute.URI_REFERENCE);

        attribute.getUnknownAttributes().put(
                new QName(getFormat().getAssertionNS(), "AttributeStatus",getFormat().getAssertionPrefix()), status);

        if (values != null) {
            LOG.trace("Add attribute values.");
            for (int i = 0; i < values.size(); i++) {
                final String value = values.get(i);
                if (StringUtils.isNotBlank(value)) {
                    XSAny attrValue = null;
                    if (!"http://www.stork.gov.eu/1.0/signedDoc".equals(name)) {
                        // Create the attribute statement
                        attrValue = createAttributeValueForNonSignedDoc(value, isHashing);

                    } else {
                        attrValue = createAttributeValueForSignedDoc(value, isHashing);
                        attribute.getAttributeValues().add(attrValue);
                    }
                    attribute.getAttributeValues().add(attrValue);
                }
            }
        }
        return attribute;
    }
    private XSAny createAttributeValueForNonSignedDoc(final String value, final boolean isHashing) throws EIDASSAMLEngineException {
        // Create the attribute statement
        final XSAny attrValue = (XSAny) SAMLEngineUtils
                .createSamlObject(
                        AttributeValue.DEFAULT_ELEMENT_NAME,
                        XSAny.TYPE_NAME);
        // if it's necessary encode the information.
        if (isHashing) {
            attrValue.setTextContent(SAMLEngineUtils.encode(value, SAMLEngineUtils.SHA_512));
        } else {
            attrValue.setTextContent(value);
        }
        if(EIDASSAMLEngine.needsTransliteration(value)){
            attrValue.getUnknownAttributes().put(new QName("LatinScript"), "false");
        }
        return attrValue;
    }

    private XSAny createAttributeValueForSignedDoc(final String value, final boolean isHashing) throws EIDASSAMLEngineException {
        DocumentBuilderFactory domFactory = EIDASSAMLEngine.newDocumentBuilderFactory();
        Document document = null;
        DocumentBuilder builder;

        // Parse the signedDoc value into an XML DOM Document
        try {
            builder = domFactory.newDocumentBuilder();
            InputStream is;
            is = new ByteArrayInputStream(value.trim().getBytes("UTF-8"));
            document = builder.parse(is);
            is.close();
        } catch (SAXException e1) {
            LOG.info(EIDASSAMLEngine.SAML_EXCHANGE, "BUSINESS EXCEPTION : SAX Error while parsing signModule attribute", e1.getMessage());
            LOG.debug(EIDASSAMLEngine.SAML_EXCHANGE, "BUSINESS EXCEPTION : SAX Error while parsing signModule attribute", e1);
            throw new EIDASSAMLEngineRuntimeException(e1);
        } catch (ParserConfigurationException e2) {
            LOG.info(EIDASSAMLEngine.SAML_EXCHANGE, "BUSINESS EXCEPTION : Parser Configuration Error while parsing signModule attribute", e2.getMessage());
            LOG.debug(EIDASSAMLEngine.SAML_EXCHANGE, "BUSINESS EXCEPTION : Parser Configuration Error while parsing signModule attribute", e2);
            throw new EIDASSAMLEngineRuntimeException(e2);
        } catch (UnsupportedEncodingException e3) {
            LOG.info(EIDASSAMLEngine.SAML_EXCHANGE, "BUSINESS EXCEPTION : Unsupported encoding Error while parsing signModule attribute", e3.getMessage());
            LOG.debug(EIDASSAMLEngine.SAML_EXCHANGE, "BUSINESS EXCEPTION : Unsupported encoding Error while parsing signModule attribute", e3);
            throw new EIDASSAMLEngineRuntimeException(e3);
        } catch (IOException e4) {
            LOG.info(EIDASSAMLEngine.SAML_EXCHANGE, "BUSINESS EXCEPTION : IO Error while parsing signModule attribute", e4.getMessage());
            LOG.debug(EIDASSAMLEngine.SAML_EXCHANGE, "BUSINESS EXCEPTION : IO Error while parsing signModule attribute", e4);
            throw new EIDASSAMLEngineRuntimeException(e4);
        }

        // Create the attribute statement
        final XSAny xmlValue = (XSAny) SAMLEngineUtils
                .createSamlObject(
                        AttributeValue.DEFAULT_ELEMENT_NAME,
                        XSAny.TYPE_NAME);

        //Set the signedDoc XML content to this element
        xmlValue.setDOM(document.getDocumentElement());

        // Create the attribute statement
        final XSAny attrValue = (XSAny) SAMLEngineUtils
                .createSamlObject(
                        AttributeValue.DEFAULT_ELEMENT_NAME,
                        XSAny.TYPE_NAME);

        //Add previous signedDocXML to the AttributeValue Element

        // if it's necessary encode the information.
        if (!isHashing) {
            attrValue.getUnknownXMLObjects().add(xmlValue);
        }
        return attrValue;
    }

}
