package eu.eidas.auth.engine.core.eidas;

import eu.eidas.auth.commons.*;
import eu.eidas.auth.engine.AbstractSAMLEngine;
import eu.eidas.auth.engine.SAMLEngineUtils;
import eu.eidas.auth.engine.EIDASSAMLEngine;
import eu.eidas.auth.engine.core.AbstractExtensionProcessor;
import eu.eidas.auth.engine.core.ExtensionProcessorI;
import eu.eidas.auth.engine.core.SAMLExtensionFormat;
import eu.eidas.auth.engine.core.eidas.impl.GenericEidasAttributeTypeBuilder;
import eu.eidas.auth.engine.core.validator.eidas.EIDASAttributes;
import eu.eidas.engine.exceptions.EIDASSAMLEngineException;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.opensaml.saml2.common.Extensions;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.impl.XSAnyImpl;
import org.opensaml.xml.schema.impl.XSStringImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.namespace.QName;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.opensaml.xml.Namespace;

import java.io.*;
import java.util.*;

public class EidasExtensionProcessor extends AbstractExtensionProcessor implements ExtensionProcessorI{
    /** The Constant LOG. */
    private static final Logger LOG = LoggerFactory.getLogger(EidasExtensionProcessor.class.getName());

    private static final String LOA_START="http://eidas.europa.eu/loa/";
    private static final String DYNAMIC_ATTRIBUTES_LOCATION = "eidas/additionalAttributes.xml";
    private static final String DYNAMIC_FULL_NAME_POSTFIX=".FullName";
    private static final int DYNAMIC_FULL_NAME_POSTFIX_LENGTH=DYNAMIC_FULL_NAME_POSTFIX.length();
    private static final String DYNAMIC_TYPE_POSTFIX=".Type";
    private static final int DYNAMIC_TYPE_POSTFIX_LENGTH=DYNAMIC_TYPE_POSTFIX.length();

    private static final String EIDAS_REQUEST_VALIDATOR_SUITE_ID = "eidasRequestValidatorSuiteId";
    public String getRequestValidatorId(){
        return EIDAS_REQUEST_VALIDATOR_SUITE_ID;
    }
    private static final String EIDAS_RESPONSE_VALIDATOR_SUITE_ID = "eidasResponseValidatorSuiteId";
    public String getResponseValidatorId(){
        return EIDAS_RESPONSE_VALIDATOR_SUITE_ID;
    }
    private EidasExtensionConfiguration configuration=new EidasExtensionConfiguration();

    /**
     * supported dynamic attributes, indexed by fullName
     */
    private static Map<String, String> dynamicAttributesFullName=null;
    /**
     * supported dynamic attributes, indexed by (short)name (ie friendlyName)
     */
    private static Map<String, String> dynamicAttributesFriendlyName=null;

    /**
     * supported dynamic attributes type, indexed by the fullname
     */
    private static Map<String, EidasAttributesTypes> dynamicAttributesTypes=null;

    /**
     * Process all elements XMLObjects from the extensions.
     *
     * @param extensions the extensions from the authentication request.
     *
     * @return the EIDAS authentication request
     *
     * @throws EIDASSAMLEngineException the EIDASSAML engine exception
     */
    public EIDASAuthnRequest processExtensions(final Extensions extensions)
            throws EIDASSAMLEngineException {
        LOG.debug("Process the extensions for EIDAS 1.0 messageFormat");

        final EIDASAuthnRequest request = new EIDASAuthnRequest();

        fillRequestSPType(request, extensions);

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
            personalAttribute.setFullName(attributeName);

            // recover the last name from the string.
            personalAttribute.setName(attributeName.substring(attributeName
                    .lastIndexOf('/') + 1));

            final List<String> stringValues = new ArrayList<String>();
            final List<XMLObject> values = attribute.getOrderedChildren();

            for (int nextSimpleValue = 0; nextSimpleValue < values.size(); nextSimpleValue++) {

                // Process attributes simples. An AuthenticationRequest only
                // must contains simple values.

                final XMLObject xmlObject = values.get(nextSimpleValue);

                if(xmlObject instanceof XSStringImpl){

                    final XSStringImpl xmlString = (XSStringImpl) values.get(nextSimpleValue);
                    stringValues.add(xmlString.getValue());

                }else{

                    if ((SAMLExtensionFormat.EIDAS10.getBaseURI()+"signedDoc").equals(attributeName)) {

                        stringValues.add(extractEDocValue((XSAnyImpl) values.get(nextSimpleValue)));

                    }else{

                        final XSAnyImpl xmlString = (XSAnyImpl) values.get(nextSimpleValue);
                        stringValues.add(xmlString.getTextContent());
                    }



                }
            }
            personalAttribute.setValue(stringValues);
            personalAttrList.add(personalAttribute);
        }

        request.setPersonalAttributeList(personalAttrList);

        return request;
    }

    private static void fillRequestSPType(EIDASAuthnRequest request,final Extensions extensions){
        List optionalElements = extensions.getUnknownXMLObjects(SPType.DEF_ELEMENT_NAME);

        if (!optionalElements.isEmpty()) {
            final SPType type = (SPType) extensions.getUnknownXMLObjects(SPType.DEF_ELEMENT_NAME).get(0);
            request.setSPType(type.getSPType());
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
    /**
     * Generate extensions.
     *
     * @param request the request
     *
     * @return the extensions
     *
     * @throws EIDASSAMLEngineException the EIDASSAML engine exception
     */
    public Extensions generateExtensions(final EIDASSAMLEngine engine, final EIDASAuthnRequest request)
            throws EIDASSAMLEngineException {
        LOG.trace("Generate EIDAS Extensions");

        final Extensions extensions = SAMLEngineUtils.generateExtension();


        addExtensionSPType(request, extensions);


        // Add information about requested attributes.
        LOG.trace("Generate RequestedAttributes.");
        final RequestedAttributes reqAttributes = (RequestedAttributes) SAMLEngineUtils
                .createSamlObject(RequestedAttributes.DEF_ELEMENT_NAME);

        fillRequestedAttributes(engine, request, reqAttributes);
        // Add requested attributes.
        extensions.getUnknownXMLObjects().add(reqAttributes);


        return extensions;

    }


    private static void addExtensionSPType(final EIDASAuthnRequest request, Extensions extensions)throws EIDASSAMLEngineException{
        String spType=request.getSPType();
        if (!StringUtils.isEmpty(spType)) {
            LOG.trace("Generate SPType");
            final SPType spTypeObj = (SPType)SAMLEngineUtils.createSamlObject(SPType.DEF_ELEMENT_NAME);
            spTypeObj.setSPType(spType);
            extensions.getUnknownXMLObjects().add(spTypeObj);
        }
    }

    private void fillRequestedAttributes(final EIDASSAMLEngine engine, final EIDASAuthnRequest request,RequestedAttributes reqAttributes)
            throws EIDASSAMLEngineException{
        LOG.trace("SAML Engine configuration properties load.");
        final Iterator<PersonalAttribute> iterator = request.getPersonalAttributeList().iterator();
        Map<String, String> dynamicAttributes = getDynamicAttributesFullName();

        while (iterator.hasNext()) {

            final PersonalAttribute attribute = iterator.next();

            if (attribute == null || StringUtils.isBlank(attribute.getName())) {
                LOG.info(EIDASSAMLEngine.SAML_EXCHANGE, EIDASSAMLEngine.ATTRIBUTE_EMPTY_LITERAL);
                throw new EIDASSAMLEngineException(EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                        EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),EIDASSAMLEngine.ATTRIBUTE_EMPTY_LITERAL);
            }

            // Verified if exists the attribute name.
            String attributeName = engine.getSamlCoreProperties().getProperty(this.namePrefix() + attribute.getName());
            if(StringUtils.isBlank(attributeName)) {
                attributeName = dynamicAttributes.get(attribute.getName());
            }

            if(StringUtils.isBlank(attributeName)) {
                attributeName = engine.getSamlCoreProperties().getProperty(attribute.getName());
            }
            if (StringUtils.isBlank(attributeName)) {
                LOG.trace("Attribute name: {} was not found.", attribute.getName());
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
            final RequestedAttribute requestedAttr = generateReqAuthnAttributeSimple(engine, attributeName,
                    friendlyName, isRequired, attribute
                            .getValue());

            // Add requested attribute.
            reqAttributes.getAttributes().add(requestedAttr);
        }

    }
    private static RequestedAttribute generateReqAuthnAttributeSimple(final EIDASSAMLEngine engine,
                                                                      final String name, final String friendlyName,
                                                                      final String isRequired, final List<String> value) {
        LOG.debug("Generate the requested attribute.");

        final RequestedAttribute requested = (RequestedAttribute) SAMLEngineUtils
                .createSamlObject(RequestedAttribute.DEF_ELEMENT_NAME);
        requested.setName(name);
        requested.setNameFormat(RequestedAttribute.URI_REFERENCE);

        requested.setFriendlyName(friendlyName);

        requested.setIsRequired(isRequired);
        SAMLEngineUtils.generateDocument(engine, name, value, requested.getAttributeValues());

        return requested;
    }

    public String namePrefix(){
        return SAMLExtensionFormat.EIDAS10.getBaseURI();
    }
    public SAMLExtensionFormat getFormat(){
        return SAMLExtensionFormat.EIDAS10;
    }

    @Override
    public void configureExtension() {
        configuration.configureExtension();
    }
    @Override
    public Set<String> getSupportedAttributes(){
        Set<String> supportedAttributes=new HashSet<String>( EIDASAttributes.ATTRIBUTES_TO_ATTRIBUTETYPE.keySet());
        if(!getDynamicAttributesFullName().isEmpty()){
            supportedAttributes.addAll(getDynamicAttributesFriendlyName().keySet());
        }
        return supportedAttributes;
    }

    @Override
    public boolean isValidRequest(AuthnRequest request){
        try {
            EIDASAuthnRequest eidasRequest = processExtensions(request.getExtensions());
            if(!StringUtils.isEmpty(eidasRequest.getSPType())){
                return true;
            }
            if(request.getRequestedAuthnContext()!=null && !request.getRequestedAuthnContext().getAuthnContextClassRefs().isEmpty()){
                for(AuthnContextClassRef accr:request.getRequestedAuthnContext().getAuthnContextClassRefs()){
                    if(accr.getAuthnContextClassRef()!=null && accr.getAuthnContextClassRef().toLowerCase().startsWith(LOA_START)){
                        return true;
                    }
                }
            }
        }catch(EIDASSAMLEngineException exc){
            LOG.debug("error validating request: "+exc);
        }
        return false;
    }

    @Override
    public Attribute generateAttrSimple(final String name,
                                        final String status, final List<String> values,
                                        final boolean isHashing) throws EIDASSAMLEngineException {
        LOG.trace("Generate attribute simple: {}", name);
        final Attribute attribute = (Attribute) SAMLEngineUtils
                .createSamlObject(Attribute.DEFAULT_ELEMENT_NAME);

        attribute.setName(name);
        attribute.setNameFormat(Attribute.URI_REFERENCE);
        attribute.setFriendlyName(EIDASAttributes.ATTRIBUTES_TO_SHORTNAMES.get(name));

        if (values != null) {
            LOG.trace("Add attribute values.");
            for (int i = 0; i < values.size(); i++) {
                final String value = values.get(i);
                if (StringUtils.isNotBlank(value)) {
                        // Create the attribute statement
                    XMLObject attrValue = createAttributeValueForNonSignedDoc(name, value, isHashing);

                    attribute.getAttributeValues().add(attrValue);
                }
            }
        }
        return attribute;
    }
    private XMLObject createAttributeValueForNonSignedDoc(final String name, final String value, final boolean isHashing) throws EIDASSAMLEngineException {
        // Create the attribute statement
        XMLObject attrValue = null;
        if(EIDASAttributes.ATTRIBUTES_TO_SHORTNAMES.containsKey(name)){
            GenericEidasAttributeType geat=new GenericEidasAttributeTypeBuilder().buildObject();
            QName qName = geat.getTypeName(name);
            GenericEidasAttributeType cfnt = (GenericEidasAttributeType)SAMLEngineUtils
                    .createSamlObject(AttributeValue.DEFAULT_ELEMENT_NAME, qName);
            cfnt.setValue(value);
            if (EIDASSAMLEngine.needsTransliteration(value)) {
                registerNamespace(cfnt);
                cfnt.getAttributeMap().put("eidas:LatinScript", "false");
            }
            attrValue=cfnt;
        }else {
            XSAny anyValue = (XSAny) SAMLEngineUtils
                    .createSamlObject( AttributeValue.DEFAULT_ELEMENT_NAME, XSAny.TYPE_NAME);
            // if it's necessary encode the information.
            if (isHashing) {
                anyValue.setTextContent(SAMLEngineUtils.encode(value, SAMLEngineUtils.SHA_512));
            } else {
                anyValue.setTextContent(value);
            }
            if (EIDASSAMLEngine.needsTransliteration(value)) {
                anyValue.getUnknownAttributes().put(new QName("LatinScript"), "false");
            }
            attrValue=anyValue;
        }
        return attrValue;
    }

    private void registerNamespace(GenericEidasAttributeType geat){
        Namespace eidasNS = new Namespace("http://eidas.europa.eu/attributes/naturalperson","eidas");
        geat.getNamespaceManager().registerNamespaceDeclaration(eidasNS);
    }

    @Override
    public String getAttributeFullName(final EIDASSAMLEngine engine, String name){
        String attrFullName=super.getAttributeFullName(engine, name);
        if(StringUtils.isEmpty(attrFullName)){
            attrFullName=getDynamicAttributesFullName().get(name);
        }
        return attrFullName;
    }

    private Map<String, String> getDynamicAttributesFullName(){
        if(dynamicAttributesFullName==null) {
            loadDynamicAttributes();
        }
        return dynamicAttributesFullName;
    }
    private Map<String, String> getDynamicAttributesFriendlyName(){
        if(dynamicAttributesFriendlyName==null) {
            loadDynamicAttributes();
        }
        return dynamicAttributesFriendlyName;
    }

    public static EidasAttributesTypes getDynamicAtributeType(String attributeName){
        if(dynamicAttributesTypes==null) {
            loadDynamicAttributes();
        }
        return dynamicAttributesTypes.get(attributeName);
    }

    private static void loadDynamicAttributes(){
        Properties dynamicAttributes = new Properties();
        InputStream is = EidasExtensionProcessor.class.getClassLoader().getResourceAsStream(DYNAMIC_ATTRIBUTES_LOCATION);
        if (is != null) {
            try {
                dynamicAttributes.loadFromXML(is);
            } catch (IOException exc) {
                LOG.error("Error loading dynamic EIDAS attributes {}", exc);
            }
            IOUtils.closeQuietly(is);
        }
        synchronized(EidasExtensionProcessor.class) {
            if(dynamicAttributesFullName==null || dynamicAttributesFriendlyName==null) {
                dynamicAttributesFriendlyName = new HashMap<String, String>();
                dynamicAttributesFullName = new HashMap<String, String>();
                dynamicAttributesTypes = new HashMap<String, EidasAttributesTypes>();
                loadAttributesNames(dynamicAttributes);
                loadAttributesTypes(dynamicAttributes);
            }
        }
    }
    private static void loadAttributesNames(Properties dynamicAttributes){
        for (Object prop : dynamicAttributes.keySet()) {
            String key = prop.toString();
            String value = dynamicAttributes.getProperty(key);
            if (key.endsWith(DYNAMIC_FULL_NAME_POSTFIX)) {
                String attrFriendlyName=key.substring(0, key.length() - DYNAMIC_FULL_NAME_POSTFIX_LENGTH);
                dynamicAttributesFriendlyName.put(value, attrFriendlyName);
                dynamicAttributesFullName.put(attrFriendlyName, value);
            }
        }

    }

    private static void loadAttributesTypes(Properties dynamicAttributes){
        for (Object prop : dynamicAttributes.keySet()) {
            String key = prop.toString();
            if (key.endsWith(DYNAMIC_TYPE_POSTFIX) ) {
                String attrFriendlyName=key.substring(0, key.length() - DYNAMIC_TYPE_POSTFIX_LENGTH);
                if(dynamicAttributesFullName.containsKey(attrFriendlyName)) {
                    dynamicAttributesTypes.put(dynamicAttributesFullName.get(attrFriendlyName), EidasAttributesTypes.dynamicFromString(dynamicAttributes.getProperty(key)));
                }
            }
        }
    }

}
