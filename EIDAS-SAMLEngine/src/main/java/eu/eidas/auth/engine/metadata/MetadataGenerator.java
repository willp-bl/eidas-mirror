/*
 * Licensed under the EUPL, Version 1.1 or – as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence");
 * You may not use this work except in compliance with the Licence. You may
 * obtain a copy of the Licence at:
 *
 * http://www.osor.eu/eupl/european-union-public-licence-eupl-v.1.1
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * Licence for the specific language governing permissions and limitations under
 * the Licence.
 */
package eu.eidas.auth.engine.metadata;

import eu.eidas.auth.commons.Constants;
import eu.eidas.auth.commons.DocumentBuilderFactoryUtil;
import eu.eidas.auth.commons.EIDASAuthnRequest;
import eu.eidas.auth.commons.EIDASUtil;
import eu.eidas.auth.engine.AbstractSAMLEngine;
import eu.eidas.auth.engine.SAMLEngineUtils;
import eu.eidas.auth.engine.EIDASSAMLEngine;
import eu.eidas.auth.engine.core.SAMLExtensionFormat;
import eu.eidas.auth.engine.core.eidas.DigestMethod;
import eu.eidas.auth.engine.core.eidas.EidasConstants;
import eu.eidas.auth.engine.core.eidas.SPType;
import eu.eidas.auth.engine.core.eidas.SigningMethod;
import eu.eidas.configuration.SAMLBootstrap;
import eu.eidas.engine.exceptions.SAMLEngineException;

import org.apache.commons.lang.StringUtils;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.joda.time.DateTime;
import org.joda.time.DurationFieldType;
import org.opensaml.Configuration;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.common.Extensions;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.metadata.*;
import org.opensaml.samlext.saml2mdattr.EntityAttributes;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.keyinfo.KeyInfoGenerator;
import org.opensaml.xml.security.x509.X509KeyInfoGeneratorFactory;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.impl.SignatureImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Metadata generator class
 */
public class MetadataGenerator {
    private static final Logger LOGGER = LoggerFactory.getLogger(MetadataGenerator.class.getName());
    MetadataConfigParams params;
    XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
    SPSSODescriptor spSSODescriptor=null;
    IDPSSODescriptor idpSSODescriptor=null;

    /**
     *
     * @return a String representation of the entityDescriptr built based on the attributes previously set
     */
    public String generateMetadata(){
        EntityDescriptor entityDescriptor = null;
        try {
            entityDescriptor = (EntityDescriptor)builderFactory.getBuilder(EntityDescriptor.DEFAULT_ELEMENT_NAME).buildObject(EntityDescriptor.DEFAULT_ELEMENT_NAME);

            entityDescriptor.setEntityID(params.getEntityID());
            entityDescriptor.setOrganization(buildOrganization());
            entityDescriptor.getContactPersons().add(buildContact(ContactPersonTypeEnumeration.SUPPORT));
            entityDescriptor.getContactPersons().add(buildContact(ContactPersonTypeEnumeration.TECHNICAL));
            entityDescriptor.setValidUntil(getExpireDate());

            X509KeyInfoGeneratorFactory keyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
            keyInfoGeneratorFactory.setEmitEntityCertificate(true);
            Extensions e=generateExtensions();
            if(!e.getUnknownXMLObjects().isEmpty()){
                entityDescriptor.setExtensions(e);
            }
            if(spSSODescriptor!=null){
                generateSPSSODescriptor(entityDescriptor, keyInfoGeneratorFactory);
            }
            if(idpSSODescriptor!=null){
                generateIDPSSODescriptor(entityDescriptor, keyInfoGeneratorFactory);
            }
            if(params.getSpEngine()!=null){
                params.getSpEngine().signEntityDescriptor(entityDescriptor);
            }else if(params.getIdpEngine()!=null){
                params.getIdpEngine().signEntityDescriptor(entityDescriptor);
            }
        }catch(SAMLEngineException se){
            LOGGER.info("ERROR : SAMLException ", se.getMessage());
            LOGGER.debug("ERROR : SAMLException ", se);
        }catch (NoSuchFieldException nsfe){
            LOGGER.info("ERROR : no such field error", nsfe.getMessage());
            LOGGER.debug("ERROR : no such field error", nsfe);
        }catch (IllegalAccessException iae){
            LOGGER.debug("ERROR : illegal access error", iae.getMessage());
            LOGGER.debug("ERROR : illegal access error", iae);
        }catch (org.opensaml.xml.security.SecurityException se){
            LOGGER.info("ERROR : security error", se.getMessage());
            LOGGER.debug("ERROR : security error", se);
        }
        return SAMLEngineUtils.serializeObject(entityDescriptor);
    }

    private void generateSPSSODescriptor(final EntityDescriptor entityDescriptor, final X509KeyInfoGeneratorFactory keyInfoGeneratorFactory)
    throws org.opensaml.xml.security.SecurityException, IllegalAccessException, NoSuchFieldException,SAMLEngineException {
        //the node has SP role
        spSSODescriptor.setWantAssertionsSigned(params.wantAssertionsSigned);
        spSSODescriptor.setAuthnRequestsSigned(true);
        spSSODescriptor.setID(idpSSODescriptor==null?params.getEntityID():(MetadataConfigParams.SP_ID_PREFIX+params.getEntityID()));
        if(params.spSignature!=null) {
            spSSODescriptor.setSignature(params.spSignature);
        }
        if(params.spSigningCredential!=null) {
            spSSODescriptor.getKeyDescriptors().add(getKeyDescriptor(keyInfoGeneratorFactory, params.spSigningCredential, UsageType.SIGNING));
        }else if(params.signingCredential!=null){
            spSSODescriptor.getKeyDescriptors().add(getKeyDescriptor(keyInfoGeneratorFactory, params.signingCredential, UsageType.SIGNING));
        }
        if(params.spEncryptionCredential!=null) {
            spSSODescriptor.getKeyDescriptors().add(getKeyDescriptor(keyInfoGeneratorFactory, params.spEncryptionCredential, UsageType.ENCRYPTION));
        }else if(params.encryptionCredential!=null){
            spSSODescriptor.getKeyDescriptors().add(getKeyDescriptor(keyInfoGeneratorFactory, params.encryptionCredential, UsageType.ENCRYPTION));
        }
        spSSODescriptor.addSupportedProtocol(params.spSamlProtocol);
        if(!StringUtils.isEmpty(params.assertionConsumerUrl)){
            addAssertionConsumerService();
        }
        fillNameIDFormat(spSSODescriptor);
        if(params.getSpEngine()!=null){
            params.getSpEngine().signDescriptor(spSSODescriptor);
        }
        entityDescriptor.getRoleDescriptors().add(spSSODescriptor);

    }
    private void fillNameIDFormat(SSODescriptor ssoDescriptor){
        NameIDFormat persistentFormat=(NameIDFormat)SAMLEngineUtils.createSamlObject(NameIDFormat.DEFAULT_ELEMENT_NAME);
        persistentFormat.setFormat(EIDASAuthnRequest.NAMEID_FORMAT_PERSISTENT);
        ssoDescriptor.getNameIDFormats().add(persistentFormat);
        NameIDFormat transientFormat=(NameIDFormat)SAMLEngineUtils.createSamlObject(NameIDFormat.DEFAULT_ELEMENT_NAME);
        transientFormat.setFormat(EIDASAuthnRequest.NAMEID_FORMAT_TRANSIENT);
        ssoDescriptor.getNameIDFormats().add(transientFormat);
        NameIDFormat unspecifiedFormat=(NameIDFormat)SAMLEngineUtils.createSamlObject(NameIDFormat.DEFAULT_ELEMENT_NAME);
        unspecifiedFormat.setFormat(EIDASAuthnRequest.NAMEID_FORMAT_UNSPECIFIED);
        ssoDescriptor.getNameIDFormats().add(unspecifiedFormat);
    }
    private void generateIDPSSODescriptor(final EntityDescriptor entityDescriptor, final X509KeyInfoGeneratorFactory keyInfoGeneratorFactory)
            throws org.opensaml.xml.security.SecurityException, IllegalAccessException, NoSuchFieldException,SAMLEngineException {
        //the node has IDP role
        idpSSODescriptor.setWantAuthnRequestsSigned(true);
        idpSSODescriptor.setID(spSSODescriptor==null?params.getEntityID():(MetadataConfigParams.IDP_ID_PREFIX+params.getEntityID()));
        if(params.idpSignature!=null) {
            idpSSODescriptor.setSignature(params.idpSignature);
        }
        if(params.idpSigningCredential!=null) {
            idpSSODescriptor.getKeyDescriptors().add(getKeyDescriptor(keyInfoGeneratorFactory, params.idpSigningCredential, UsageType.SIGNING));
        }else if(params.signingCredential!=null){
            idpSSODescriptor.getKeyDescriptors().add(getKeyDescriptor(keyInfoGeneratorFactory, params.signingCredential, UsageType.SIGNING));
        }
        if(params.idpEncryptionCredential!=null) {
            idpSSODescriptor.getKeyDescriptors().add(getKeyDescriptor(keyInfoGeneratorFactory, params.idpEncryptionCredential, UsageType.ENCRYPTION));
        }else if(params.encryptionCredential!=null){
            idpSSODescriptor.getKeyDescriptors().add(getKeyDescriptor(keyInfoGeneratorFactory, params.encryptionCredential, UsageType.ENCRYPTION));
        }
        idpSSODescriptor.addSupportedProtocol(params.idpSamlProtocol);
        fillNameIDFormat(idpSSODescriptor);
        if(params.getIdpEngine()!=null){
            if(params.getIdpEngine().getExtensionProcessor()!=null &&params.getIdpEngine().getExtensionProcessor().getFormat()== SAMLExtensionFormat.EIDAS10){
                generateSupportedAttributes(idpSSODescriptor, params.getIdpEngine().getExtensionProcessor().getSupportedAttributes());
            }
            params.getIdpEngine().signDescriptor(idpSSODescriptor);
        }
        entityDescriptor.getRoleDescriptors().add(idpSSODescriptor);

    }

    /**
     *
     * @param metadata
     * @return an EntityDescriptor parsed from the given String
     */

    public EntityDescriptorContainer deserializeEntityDescriptor(String metadata){
    	EntityDescriptorContainer result=new EntityDescriptorContainer(); 
        try{
            BasicParserPool parsePool = AbstractSAMLEngine.getNewBasicSecuredParserPool();
            Document document = parsePool.parse(new ByteArrayInputStream(metadata.getBytes(Charset.forName(Constants.UTF8_ENCODING))));
            Unmarshaller in = Configuration.getUnmarshallerFactory().getUnmarshaller(document.getDocumentElement());
            XMLObject obj = in.unmarshall(document.getDocumentElement());
            if(obj instanceof  EntityDescriptor){
                result.addEntityDescriptor((EntityDescriptor)obj, metadata.getBytes(Constants.UTF8_ENCODING));
            }else if(obj instanceof EntitiesDescriptor){
            	EntitiesDescriptor ed = (EntitiesDescriptor)obj;
            	result.setEntitiesDescriptor(ed);
            	result.getEntityDescriptors().addAll(((EntitiesDescriptor)obj).getEntityDescriptors());
            	result.setSerializedEntitesDescriptor(metadata.getBytes(Constants.UTF8_ENCODING));
            }
        }catch(UnsupportedEncodingException uee){
            LOGGER.info("ERROR : encoding error", uee.getMessage());
            LOGGER.debug("ERROR : encoding error", uee);
        }catch(XMLParserException pe){
            LOGGER.info("ERROR : parser error", pe.getMessage());
            LOGGER.debug("ERROR : parser error", pe);
        }catch (UnmarshallingException ume) {
            LOGGER.info("ERROR : unmarshalling error", ume.getMessage());
            LOGGER.debug("ERROR : unmarshalling error", ume);
        }
        return result;
    }

    private KeyDescriptor getKeyDescriptor (X509KeyInfoGeneratorFactory keyInfoGeneratorFactory, Credential credential, UsageType usage) throws NoSuchFieldException,IllegalAccessException,SecurityException{
        KeyDescriptor keyDescriptor=null;
        if(credential!=null) {
            keyDescriptor= SAMLEngineUtils.createSAMLObject(KeyDescriptor.class);
            KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();

            KeyInfo keyInfo = keyInfoGenerator.generate(credential);
            keyDescriptor.setUse(usage);
            keyDescriptor.setKeyInfo(keyInfo);
            if(usage==UsageType.ENCRYPTION && params.getEncryptionAlgorithms()!=null){
                Set<String> encryptionAlgos=EIDASUtil.parseSemicolonSeparatedList(params.getEncryptionAlgorithms());
                for(String encryptionAlgo:encryptionAlgos) {
                    EncryptionMethod em = (EncryptionMethod) SAMLEngineUtils.createSamlObject(EncryptionMethod.DEFAULT_ELEMENT_NAME);
                    em.setAlgorithm(encryptionAlgo);
                    keyDescriptor.getEncryptionMethods().add(em);
                }
            }

        }
        return keyDescriptor;
    }

    private Organization buildOrganization(){
        Organization organization=null;
        try {
            organization = SAMLEngineUtils.createSAMLObject(Organization.class);
            OrganizationDisplayName odn= SAMLEngineUtils.createSAMLObject(OrganizationDisplayName.class);
            odn.setName(new LocalizedString(params.countryName, MetadataConfigParams.DEFAULT_LANG));
            organization.getDisplayNames().add(odn);
            OrganizationURL url= SAMLEngineUtils.createSAMLObject(OrganizationURL.class);
            url.setURL(new LocalizedString(params.nodeUrl, MetadataConfigParams.DEFAULT_LANG));
            organization.getURLs().add(url);
        }catch(IllegalAccessException iae){
            LOGGER.info("ERROR : error generating the Organization: {}", iae.getMessage());
            LOGGER.debug("ERROR : error generating the Organization: {}", iae);
        }catch(NoSuchFieldException nfe){
            LOGGER.info("ERROR : error generating the Organization: {}", nfe.getMessage());
            LOGGER.debug("ERROR : error generating the Organization: {}", nfe);
        }
        return organization;
    }
    private ContactPerson buildContact(ContactPersonTypeEnumeration contactType){
        ContactPerson contact=null;
        try {
            Contact currentContact=null;
            if(contactType==ContactPersonTypeEnumeration.SUPPORT) {
                currentContact = params.getSupportContact();
            }else if(contactType==ContactPersonTypeEnumeration.TECHNICAL){
                currentContact = params.getTechnicalContact();
            }else{
                LOGGER.error("ERROR: unsupported contact type");
            }
            contact = SAMLEngineUtils.createSAMLObject(ContactPerson.class);
            if(currentContact==null){
                LOGGER.error("ERROR: cannot retrieve contact from the configuration");
                return contact;
            }

            EmailAddress emailAddressObj= SAMLEngineUtils.createSAMLObject(EmailAddress.class);
            Company company=SAMLEngineUtils.createSAMLObject(Company.class);
            GivenName givenName=SAMLEngineUtils.createSAMLObject(GivenName.class);
            SurName surName=SAMLEngineUtils.createSAMLObject(SurName.class);
            TelephoneNumber phoneNumber=SAMLEngineUtils.createSAMLObject(TelephoneNumber.class);
            contact.setType(contactType);
            emailAddressObj.setAddress(currentContact.getEmail());
            company.setName(currentContact.getCompany());
            givenName.setName(currentContact.getGivenName());
            surName.setName(currentContact.getSurName());
            phoneNumber.setNumber(currentContact.getPhone());

            populateContact(contact, currentContact, emailAddressObj, company, givenName, surName, phoneNumber);

        }catch(IllegalAccessException iae){
            LOGGER.info("ERROR : error generating the Organization: {}", iae.getMessage());
            LOGGER.debug("ERROR : error generating the Organization: {}", iae);
        }catch(NoSuchFieldException nfe){
            LOGGER.info("ERROR : error generating the Organization: {}", nfe.getMessage());
            LOGGER.debug("ERROR : error generating the Organization: {}", nfe);
        }
        return contact;
    }
    private void populateContact(ContactPerson contact, Contact currentContact, EmailAddress emailAddressObj,
                                 Company company, GivenName givenName,SurName surName, TelephoneNumber phoneNumber){
        if(!StringUtils.isEmpty(currentContact.getEmail())) {
            contact.getEmailAddresses().add(emailAddressObj);
        }
        if(!StringUtils.isEmpty(currentContact.getCompany())) {
            contact.setCompany(company);
        }
        if(!StringUtils.isEmpty(currentContact.getGivenName())) {
            contact.setGivenName(givenName);
        }
        if(!StringUtils.isEmpty(currentContact.getSurName())) {
            contact.setSurName(surName);
        }
        if(!StringUtils.isEmpty(currentContact.getPhone())) {
            contact.getTelephoneNumbers().add(phoneNumber);
        }

    }
    /**
     *
     * @param engine a EIDASSamlEngine from which signing and encryption information is extracted
     */

    public void initialize(EIDASSAMLEngine engine) throws SAMLEngineException {
        try {
            params.setIDPSignature(engine.getSignature());
            params.setSPSignature(engine.getSignature());
            params.setEncryptionCredential(engine.getEncryptionCredential());
            params.setSigningCredential(engine.getSigningCredential());
            params.setIdpEngine(engine);
            params.setSpEngine(engine);
        }catch(SAMLEngineException see){
            LOGGER.info("ERROR : error during initialization from samlengine: {}", see.getMessage());
            LOGGER.debug("ERROR : error during initialization from samlengine: {}", see);
            throw see;
        }
    }

    /**
     *
     * @param spEngine a EIDASSamlEngine for the
     */

    public void initialize(EIDASSAMLEngine spEngine, EIDASSAMLEngine idpEngine) throws SAMLEngineException{
        try {
            if(idpEngine!=null) {
                idpEngine.getExtensionProcessor().configureExtension();
                params.setIDPSignature(idpEngine.getSignature());
                params.setIdpSigningCredential(idpEngine.getSigningCredential());
                params.setIdpEncryptionCredential(idpEngine.getEncryptionCredential());
            }
            if(spEngine!=null) {
                spEngine.getExtensionProcessor().configureExtension();
                params.setSPSignature(spEngine.getSignature());
                params.setSpSigningCredential(spEngine.getSigningCredential());
                params.setSpEncryptionCredential(spEngine.getEncryptionCredential());
            }

            params.setIdpEngine(idpEngine);
            params.setSpEngine(spEngine);
        }catch(SAMLEngineException see){
            LOGGER.info("ERROR : error during initialization from samlengine: {}", see.getMessage());
            LOGGER.debug("ERROR : error during initialization from samlengine: {}", see);
            throw see;
        }
    }

    public void addSPRole() throws SAMLEngineException {
        try {
            if (spSSODescriptor == null) {
                spSSODescriptor = SAMLEngineUtils.createSAMLObject(SPSSODescriptor.class);
            }
        }catch(IllegalAccessException iae){
            throw new SAMLEngineException(iae);
        }catch( NoSuchFieldException nsfe){
            throw new SAMLEngineException(nsfe);
        }
    }
    public void addIDPRole() throws SAMLEngineException {
        try {
            if(idpSSODescriptor==null) {
                idpSSODescriptor = SAMLEngineUtils.createSAMLObject(IDPSSODescriptor.class);
            }
        }catch(IllegalAccessException iae){
            throw new SAMLEngineException(iae);
        }catch( NoSuchFieldException nsfe){
            throw new SAMLEngineException(nsfe);
        }
    }

    private void generateDigest(Extensions eidasExtensions){
        if(!StringUtils.isEmpty(params.getDigestMethods())){
            Set<String> signatureMethods= EIDASUtil.parseSemicolonSeparatedList(params.getDigestMethods());
            Set<String> digestMethods=new HashSet<String>();
            for(String signatureMethod:signatureMethods) {
                digestMethods.add(SAMLEngineUtils.validateDigestAlgorithm(signatureMethod));
            }
            for(String digestMethod:digestMethods){
                final DigestMethod dm = (DigestMethod) SAMLEngineUtils.createSamlObject(DigestMethod.DEF_ELEMENT_NAME);
                if (dm != null) {
                    dm.setAlgorithm(digestMethod);
                    eidasExtensions.getUnknownXMLObjects().add(dm);
                } else {
                    LOGGER.info("BUSINESS EXCEPTION error adding DigestMethod extension");
                }
            }
        }

    }
    private Extensions generateExtensions(){
        Extensions eidasExtensions=SAMLEngineUtils.generateExtension();
        if(params.assuranceLevel!=null){
            generateLoA(eidasExtensions);
        }
        if(!StringUtils.isEmpty(params.getSpType())){
            final SPType spTypeObj = (SPType)SAMLEngineUtils.createSamlObject(SPType.DEF_ELEMENT_NAME);
            if(spTypeObj!=null) {
                spTypeObj.setSPType(params.getSpType());
                eidasExtensions.getUnknownXMLObjects().add(spTypeObj);
            }else{
                LOGGER.info("BUSINESS EXCEPTION error adding SPType extension");
            }
        }
        generateDigest(eidasExtensions);

        if(!StringUtils.isEmpty(params.getSigningMethods())){
            Set<String> signMethods= EIDASUtil.parseSemicolonSeparatedList(params.getDigestMethods());
            for(String signMethod:signMethods) {
                final SigningMethod sm = (SigningMethod) SAMLEngineUtils.createSamlObject(SigningMethod.DEF_ELEMENT_NAME);
                if (sm != null) {
                    sm.setAlgorithm(signMethod);
                    eidasExtensions.getUnknownXMLObjects().add(sm);
                } else {
                    LOGGER.info("BUSINESS EXCEPTION error adding SigningMethod extension");
                }
            }
        }
        return eidasExtensions;
    }

    private void generateLoA(Extensions eidasExtensions){
        EntityAttributes loa=(EntityAttributes)SAMLEngineUtils.createSamlObject(EntityAttributes.DEFAULT_ELEMENT_NAME);
        Attribute loaAttrib=(Attribute)SAMLEngineUtils.createSamlObject(Attribute.DEFAULT_ELEMENT_NAME);
        loaAttrib.setName(EidasConstants.LEVEL_OF_ASSURANCE_NAME);
        loaAttrib.setNameFormat(Attribute.URI_REFERENCE);
        XSStringBuilder stringBuilder = (XSStringBuilder) Configuration.getBuilderFactory().getBuilder(XSString.TYPE_NAME);
        XSString stringValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
        stringValue.setValue(params.assuranceLevel);
        loaAttrib.getAttributeValues().add(stringValue);
        loa.getAttributes().add(loaAttrib);
        eidasExtensions.getUnknownXMLObjects().add(loa);

    }

    private static final Set<String> DEFAULT_BINDING=new HashSet<String>(){{this.add(SAMLConstants.SAML2_POST_BINDING_URI);}};
    private void addAssertionConsumerService(){
    	int index=0;
    	Set<String> bindings=params.getProtocolBinding().isEmpty()?DEFAULT_BINDING:params.getProtocolBinding();
        for(String binding:bindings) {
            AssertionConsumerService asc = (AssertionConsumerService) SAMLEngineUtils.createSamlObject(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
            asc.setLocation(params.assertionConsumerUrl);
            asc.setBinding(checkBinding(binding));
            asc.setIndex(index);
            if(index==0) {
                asc.setIsDefault(true);
            }
            index++;
            spSSODescriptor.getAssertionConsumerServices().add(asc);
        }
    }

    private String checkBinding(String binding){
        if(binding!=null && (binding.equals(SAMLConstants.SAML2_REDIRECT_BINDING_URI) || binding.equals(SAMLConstants.SAML2_POST_BINDING_URI))){
            return binding;
        }
        return SAMLConstants.SAML2_POST_BINDING_URI;
    }

    private DateTime getExpireDate(){
        DateTime expiryDate=DateTime.now();
        expiryDate = expiryDate.withFieldAdded(DurationFieldType.seconds(), (int)(getConfigParams().getValidityDuration()));
        return expiryDate;
    }
    private void generateSupportedAttributes(IDPSSODescriptor idpssoDescriptor, Set<String> qualifiedNames){
        List<Attribute> attributes = idpssoDescriptor.getAttributes();
        for(String name:qualifiedNames){
            Attribute a=(Attribute)SAMLEngineUtils.createSamlObject(Attribute.DEFAULT_ELEMENT_NAME);
            a.setName(name);
            attributes.add(a);
        }
    }

    public MetadataConfigParams getConfigParams() {
        return params;
    }

    public void setConfigParams(MetadataConfigParams params) {
        this.params = params;
    }
}
