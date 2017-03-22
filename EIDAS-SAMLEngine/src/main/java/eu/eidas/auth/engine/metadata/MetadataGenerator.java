/*
 * Copyright (c) 2016 by European Commission
 *
 * Licensed under the EUPL, Version 1.1 or - as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence");
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 * http://www.osor.eu/eupl/european-union-public-licence-eupl-v.1.1
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 *
 * This product combines work with different licenses. See the "NOTICE" text
 * file for details on the various modules and licenses.
 * The "NOTICE" text file is part of the distribution. Any derivative works
 * that you distribute must include a readable copy of the "NOTICE" text file.
 *
 */

package eu.eidas.auth.engine.metadata;

import java.security.cert.X509Certificate;
import java.util.*;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import com.google.common.collect.ImmutableSortedSet;

import org.apache.commons.lang.StringUtils;
import org.joda.time.DateTime;
import org.joda.time.DurationFieldType;
import org.opensaml.Configuration;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.common.Extensions;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.metadata.*;
import org.opensaml.samlext.saml2mdattr.EntityAttributes;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.keyinfo.KeyInfoGenerator;
import org.opensaml.xml.security.x509.X509KeyInfoGeneratorFactory;
import org.opensaml.xml.signature.KeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.eidas.auth.commons.EIDASUtil;
import eu.eidas.auth.commons.EidasStringUtil;
import eu.eidas.auth.commons.attribute.AttributeDefinition;
import eu.eidas.auth.commons.protocol.impl.SamlNameIdFormat;
import eu.eidas.auth.commons.xml.opensaml.OpenSamlHelper;
import eu.eidas.auth.engine.ProtocolEngineI;
import eu.eidas.auth.engine.core.SAMLExtensionFormat;
import eu.eidas.auth.engine.core.eidas.DigestMethod;
import eu.eidas.auth.engine.core.eidas.EidasConstants;
import eu.eidas.auth.engine.core.eidas.SPType;
import eu.eidas.auth.engine.core.eidas.SigningMethod;
import eu.eidas.auth.engine.xml.opensaml.BuilderFactoryUtil;
import eu.eidas.auth.engine.xml.opensaml.CertificateUtil;
import eu.eidas.encryption.exception.UnmarshallException;
import eu.eidas.engine.exceptions.EIDASSAMLEngineException;
import eu.eidas.engine.exceptions.SAMLEngineException;

/**
 * Metadata generator class
 */
public class MetadataGenerator {

    private static final Logger LOGGER = LoggerFactory.getLogger(MetadataGenerator.class.getName());

    MetadataConfigParams params;

    XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

    SPSSODescriptor spSSODescriptor = null;

    IDPSSODescriptor idpSSODescriptor = null;

    protected String ssoLocation;

    protected static final String TECHNICAL_CONTACT_PROPS[]={"contact.technical.company", "contact.technical.email", "contact.technical.givenname", "contact.technical.surname", "contact.technical.phone"};
    protected static final String SUPPORT_CONTACT_PROPS[]={"contact.support.company", "contact.support.email", "contact.support.givenname", "contact.support.surname", "contact.support.phone"};
    protected static final String CONTACTS[][]={TECHNICAL_CONTACT_PROPS, SUPPORT_CONTACT_PROPS};

    private static final Set<String> DEFAULT_BINDING = new HashSet<String>() {{
        this.add(SAMLConstants.SAML2_POST_BINDING_URI);
    }};

    /**
     * @return a String representation of the entityDescriptr built based on the attributes previously set
     */
    public String generateMetadata() throws EIDASSAMLEngineException {
        EntityDescriptor entityDescriptor;
        try {
            entityDescriptor = (EntityDescriptor) builderFactory.getBuilder(EntityDescriptor.DEFAULT_ELEMENT_NAME)
                    .buildObject(EntityDescriptor.DEFAULT_ELEMENT_NAME);

            entityDescriptor.setEntityID(params.getEntityID());
            entityDescriptor.setOrganization(buildOrganization());
            entityDescriptor.getContactPersons().add(buildContact(ContactPersonTypeEnumeration.SUPPORT));
            entityDescriptor.getContactPersons().add(buildContact(ContactPersonTypeEnumeration.TECHNICAL));
            entityDescriptor.setValidUntil(getExpireDate());

            X509KeyInfoGeneratorFactory keyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
            keyInfoGeneratorFactory.setEmitEntityCertificate(true);
            Extensions e = generateExtensions();
            if (!e.getUnknownXMLObjects().isEmpty()) {
                entityDescriptor.setExtensions(e);
            }
            if (spSSODescriptor != null) {
                generateSPSSODescriptor(entityDescriptor, keyInfoGeneratorFactory);
            }
            if (idpSSODescriptor != null) {
                generateIDPSSODescriptor(entityDescriptor, keyInfoGeneratorFactory);
            }
            if (params.getSpEngine() != null) {
                ProtocolEngineI spEngine = params.getSpEngine();
                ((MetadataSignerI) spEngine.getSigner()).signMetadata(entityDescriptor);
            } else if (params.getIdpEngine() != null) {
                ProtocolEngineI idpEngine = params.getIdpEngine();
                ((MetadataSignerI) idpEngine.getSigner()).signMetadata(entityDescriptor);
            }
            return EidasStringUtil.toString(OpenSamlHelper.marshall(entityDescriptor, false));
        } catch (Exception ex) {
            LOGGER.info("ERROR : SAMLException ", ex.getMessage());
            LOGGER.debug("ERROR : SAMLException ", ex);
            throw new IllegalStateException(ex);
        }
    }

    private void generateSPSSODescriptor(final EntityDescriptor entityDescriptor,
                                         final X509KeyInfoGeneratorFactory keyInfoGeneratorFactory)
            throws org.opensaml.xml.security.SecurityException, IllegalAccessException, NoSuchFieldException,
                   SAMLEngineException, EIDASSAMLEngineException {
        //the node has SP role
        spSSODescriptor.setWantAssertionsSigned(params.wantAssertionsSigned);
        spSSODescriptor.setAuthnRequestsSigned(true);
        if (params.spSignature != null) {
            spSSODescriptor.setSignature(params.spSignature);
        }
        if (params.spSigningCredential != null) {
            spSSODescriptor.getKeyDescriptors()
                    .add(getKeyDescriptor(keyInfoGeneratorFactory, params.spSigningCredential, UsageType.SIGNING));
        } else if (params.signingCredential != null) {
            spSSODescriptor.getKeyDescriptors()
                    .add(getKeyDescriptor(keyInfoGeneratorFactory, params.signingCredential, UsageType.SIGNING));
        }
        if (params.spEncryptionCredential != null) {
            spSSODescriptor.getKeyDescriptors()
                    .add(getKeyDescriptor(keyInfoGeneratorFactory, params.spEncryptionCredential,
                                          UsageType.ENCRYPTION));
        } else if (params.encryptionCredential != null) {
            spSSODescriptor.getKeyDescriptors()
                    .add(getKeyDescriptor(keyInfoGeneratorFactory, params.encryptionCredential, UsageType.ENCRYPTION));
        }
        spSSODescriptor.addSupportedProtocol(params.spSamlProtocol);
        if (!StringUtils.isEmpty(params.assertionConsumerUrl)) {
            addAssertionConsumerService();
        }
        fillNameIDFormat(spSSODescriptor);
        entityDescriptor.getRoleDescriptors().add(spSSODescriptor);

    }

    private void fillNameIDFormat(SSODescriptor ssoDescriptor) throws EIDASSAMLEngineException {
        NameIDFormat persistentFormat =
                (NameIDFormat) BuilderFactoryUtil.buildXmlObject(NameIDFormat.DEFAULT_ELEMENT_NAME);
        persistentFormat.setFormat(SamlNameIdFormat.PERSISTENT.getNameIdFormat());
        ssoDescriptor.getNameIDFormats().add(persistentFormat);
        NameIDFormat transientFormat =
                (NameIDFormat) BuilderFactoryUtil.buildXmlObject(NameIDFormat.DEFAULT_ELEMENT_NAME);
        transientFormat.setFormat(SamlNameIdFormat.TRANSIENT.getNameIdFormat());
        ssoDescriptor.getNameIDFormats().add(transientFormat);
        NameIDFormat unspecifiedFormat =
                (NameIDFormat) BuilderFactoryUtil.buildXmlObject(NameIDFormat.DEFAULT_ELEMENT_NAME);
        unspecifiedFormat.setFormat(SamlNameIdFormat.UNSPECIFIED.getNameIdFormat());
        ssoDescriptor.getNameIDFormats().add(unspecifiedFormat);
    }

    @SuppressWarnings("squid:S2583")
    private void generateIDPSSODescriptor(final EntityDescriptor entityDescriptor,
                                          final X509KeyInfoGeneratorFactory keyInfoGeneratorFactory)
            throws org.opensaml.xml.security.SecurityException, IllegalAccessException, NoSuchFieldException,
                   SAMLEngineException, EIDASSAMLEngineException {
        //the node has IDP role
        idpSSODescriptor.setWantAuthnRequestsSigned(true);
        if (params.idpSignature != null) {
            idpSSODescriptor.setSignature(params.idpSignature);
        }
        if (params.idpSigningCredential != null) {
            idpSSODescriptor.getKeyDescriptors()
                    .add(getKeyDescriptor(keyInfoGeneratorFactory, params.idpSigningCredential, UsageType.SIGNING));
        } else if (params.signingCredential != null) {
            idpSSODescriptor.getKeyDescriptors()
                    .add(getKeyDescriptor(keyInfoGeneratorFactory, params.signingCredential, UsageType.SIGNING));
        }
        if (params.idpEncryptionCredential != null) {
            idpSSODescriptor.getKeyDescriptors()
                    .add(getKeyDescriptor(keyInfoGeneratorFactory, params.idpEncryptionCredential,
                                          UsageType.ENCRYPTION));
        } else if (params.encryptionCredential != null) {
            idpSSODescriptor.getKeyDescriptors()
                    .add(getKeyDescriptor(keyInfoGeneratorFactory, params.encryptionCredential, UsageType.ENCRYPTION));
        }
        idpSSODescriptor.addSupportedProtocol(params.idpSamlProtocol);
        fillNameIDFormat(idpSSODescriptor);
        idpSSODescriptor.getSingleSignOnServices().addAll(buildSingleSignOnServicesBindingLocations());
        if (params.getIdpEngine() != null &&
             (params.getIdpEngine().getProtocolProcessor() != null && params.getIdpEngine().getProtocolProcessor().getFormat() == SAMLExtensionFormat.EIDAS10)) {
            generateSupportedAttributes(idpSSODescriptor, params.getIdpEngine().getProtocolProcessor().getAllSupportedAttributes());
        }
        entityDescriptor.getRoleDescriptors().add(idpSSODescriptor);

    }

    private ArrayList<SingleSignOnService> buildSingleSignOnServicesBindingLocations()
            throws NoSuchFieldException, IllegalAccessException {
        ArrayList<SingleSignOnService> singleSignOnServices = new ArrayList<SingleSignOnService>();

        HashMap<String, String> bindingLocations = params.getProtocolBindingLocation();
        Iterator<Map.Entry<String, String>> bindLocs = bindingLocations.entrySet().iterator();
        while (bindLocs.hasNext()) {
            Map.Entry<String, String> bindingLoc = bindLocs.next();
            SingleSignOnService ssos = BuilderFactoryUtil.buildXmlObject(SingleSignOnService.class);
            ssos.setBinding(bindingLoc.getKey());
            ssos.setLocation(bindingLoc.getValue());
            singleSignOnServices.add(ssos);
        }
        return singleSignOnServices;
    }

    /**
     * @param metadata
     * @return an EntityDescriptor parsed from the given String or null
     */
    // TODO (commented by donydgr) Move to a eu.eidas.auth.engine.metadata.MetadataUtil ? Throw an exception if the metadata is invalid instead of returning null ?
    @Nullable
    public static EntityDescriptorContainer deserializeEntityDescriptor(@Nonnull String metadata) {
        EntityDescriptorContainer result = new EntityDescriptorContainer();
        try {
            byte[] metaDataBytes = EidasStringUtil.getBytes(metadata);
            XMLObject obj = OpenSamlHelper.unmarshall(metaDataBytes);
            if (obj instanceof EntityDescriptor) {
                result.addEntityDescriptor((EntityDescriptor) obj, metaDataBytes);
            } else if (obj instanceof EntitiesDescriptor) {
                EntitiesDescriptor ed = (EntitiesDescriptor) obj;
                result.setEntitiesDescriptor(ed);
                result.getEntityDescriptors().addAll(((EntitiesDescriptor) obj).getEntityDescriptors());
                result.setSerializedEntitesDescriptor(metaDataBytes);
            }
        } catch (UnmarshallException ue) {
            LOGGER.info("ERROR : unmarshalling error", ue.getMessage());
            LOGGER.debug("ERROR : unmarshalling error", ue);
        }
        return result;
    }

    private KeyDescriptor getKeyDescriptor(X509KeyInfoGeneratorFactory keyInfoGeneratorFactory,
                                           Credential credential,
                                           UsageType usage)
            throws NoSuchFieldException, IllegalAccessException, SecurityException, EIDASSAMLEngineException {
        KeyDescriptor keyDescriptor = null;
        if (credential != null) {
            keyDescriptor = BuilderFactoryUtil.buildXmlObject(KeyDescriptor.class);
            KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();

            KeyInfo keyInfo = keyInfoGenerator.generate(credential);
            keyDescriptor.setUse(usage);
            keyDescriptor.setKeyInfo(keyInfo);
            if (usage == UsageType.ENCRYPTION && params.getEncryptionAlgorithms() != null) {
                Set<String> encryptionAlgos = EIDASUtil.parseSemicolonSeparatedList(params.getEncryptionAlgorithms());
                for (String encryptionAlgo : encryptionAlgos) {
                    EncryptionMethod em =
                            (EncryptionMethod) BuilderFactoryUtil.buildXmlObject(EncryptionMethod.DEFAULT_ELEMENT_NAME);
                    em.setAlgorithm(encryptionAlgo);
                    keyDescriptor.getEncryptionMethods().add(em);
                }
            }

        }
        return keyDescriptor;
    }

    private Organization buildOrganization() {
        Organization organization = null;
        try {
            organization = BuilderFactoryUtil.buildXmlObject(Organization.class);
            OrganizationDisplayName odn = BuilderFactoryUtil.buildXmlObject(OrganizationDisplayName.class);
            odn.setName(new LocalizedString(params.countryName, MetadataConfigParams.DEFAULT_LANG));
            organization.getDisplayNames().add(odn);
            OrganizationURL url = BuilderFactoryUtil.buildXmlObject(OrganizationURL.class);
            url.setURL(new LocalizedString(params.nodeUrl, MetadataConfigParams.DEFAULT_LANG));
            organization.getURLs().add(url);
            OrganizationName on = BuilderFactoryUtil.buildXmlObject(OrganizationName.class);
            on.setName(new LocalizedString(params.getOrganizationName(), MetadataConfigParams.DEFAULT_LANG));
            organization.getOrganizationNames().add(on);
        } catch (IllegalAccessException iae) {
            LOGGER.info("ERROR : error generating the Organization: {}", iae.getMessage());
            LOGGER.debug("ERROR : error generating the Organization: {}", iae);
        } catch (NoSuchFieldException nfe) {
            LOGGER.info("ERROR : error generating the Organization: {}", nfe.getMessage());
            LOGGER.debug("ERROR : error generating the Organization: {}", nfe);
        }
        return organization;
    }

    private ContactPerson buildContact(ContactPersonTypeEnumeration contactType) {
        ContactPerson contact = null;
        try {
            Contact currentContact = null;
            if (contactType == ContactPersonTypeEnumeration.SUPPORT) {
                currentContact = params.getSupportContact();
            } else if (contactType == ContactPersonTypeEnumeration.TECHNICAL) {
                currentContact = params.getTechnicalContact();
            } else {
                LOGGER.error("ERROR: unsupported contact type");
            }
            contact = BuilderFactoryUtil.buildXmlObject(ContactPerson.class);
            if (currentContact == null) {
                LOGGER.error("ERROR: cannot retrieve contact from the configuration");
                return contact;
            }

            EmailAddress emailAddressObj = BuilderFactoryUtil.buildXmlObject(EmailAddress.class);
            Company company = BuilderFactoryUtil.buildXmlObject(Company.class);
            GivenName givenName = BuilderFactoryUtil.buildXmlObject(GivenName.class);
            SurName surName = BuilderFactoryUtil.buildXmlObject(SurName.class);
            TelephoneNumber phoneNumber = BuilderFactoryUtil.buildXmlObject(TelephoneNumber.class);
            contact.setType(contactType);
            emailAddressObj.setAddress(currentContact.getEmail());
            company.setName(currentContact.getCompany());
            givenName.setName(currentContact.getGivenName());
            surName.setName(currentContact.getSurName());
            phoneNumber.setNumber(currentContact.getPhone());

            populateContact(contact, currentContact, emailAddressObj, company, givenName, surName, phoneNumber);

        } catch (IllegalAccessException iae) {
            LOGGER.info("ERROR : error generating the Organization: {}", iae.getMessage());
            LOGGER.debug("ERROR : error generating the Organization: {}", iae);
        } catch (NoSuchFieldException nfe) {
            LOGGER.info("ERROR : error generating the Organization: {}", nfe.getMessage());
            LOGGER.debug("ERROR : error generating the Organization: {}", nfe);
        }
        return contact;
    }

    private void populateContact(ContactPerson contact,
                                 Contact currentContact,
                                 EmailAddress emailAddressObj,
                                 Company company,
                                 GivenName givenName,
                                 SurName surName,
                                 TelephoneNumber phoneNumber) {
        if (!StringUtils.isEmpty(currentContact.getEmail())) {
            contact.getEmailAddresses().add(emailAddressObj);
        }
        if (!StringUtils.isEmpty(currentContact.getCompany())) {
            contact.setCompany(company);
        }
        if (!StringUtils.isEmpty(currentContact.getGivenName())) {
            contact.setGivenName(givenName);
        }
        if (!StringUtils.isEmpty(currentContact.getSurName())) {
            contact.setSurName(surName);
        }
        if (!StringUtils.isEmpty(currentContact.getPhone())) {
            contact.getTelephoneNumbers().add(phoneNumber);
        }

    }

    /**
     * @param engine a EIDASSamlEngine from which signing and encryption information is extracted
     */

    public void initialize(ProtocolEngineI engine) throws EIDASSAMLEngineException {

        X509Certificate decryptionCertificate = engine.getDecryptionCertificate();
        if (null != decryptionCertificate) {
            params.setEncryptionCredential(CertificateUtil.toCredential(decryptionCertificate));
        }
        params.setSigningCredential(CertificateUtil.toCredential(engine.getSigningCertificate()));
        params.setIdpEngine(engine);
        params.setSpEngine(engine);
    }

    /**
     * @param spEngine a EIDASSamlEngine for the
     */

    public void initialize(ProtocolEngineI spEngine, ProtocolEngineI idpEngine) throws EIDASSAMLEngineException {
        if (idpEngine != null) {
            idpEngine.getProtocolProcessor().configure();
            params.setIdpSigningCredential(CertificateUtil.toCredential(idpEngine.getSigningCertificate()));

            final X509Certificate idpEngineDecryptionCertificate = idpEngine.getDecryptionCertificate();
            if (idpEngineDecryptionCertificate != null) {
                params.setIdpEncryptionCredential(CertificateUtil.toCredential(idpEngineDecryptionCertificate));
            }

        }
        if (spEngine != null) {
            spEngine.getProtocolProcessor().configure();
            params.setSpSigningCredential(CertificateUtil.toCredential(spEngine.getSigningCertificate()));

            final X509Certificate spEngineDecryptionCertificate = spEngine.getDecryptionCertificate();
            if (spEngineDecryptionCertificate != null) {
                params.setSpEncryptionCredential(CertificateUtil.toCredential(spEngineDecryptionCertificate));
            }
        }

        params.setIdpEngine(idpEngine);
        params.setSpEngine(spEngine);
    }

    public void addSPRole() throws EIDASSAMLEngineException {
        try {
            if (spSSODescriptor == null) {
                spSSODescriptor = BuilderFactoryUtil.buildXmlObject(SPSSODescriptor.class);
            }
        } catch (IllegalAccessException iae) {
            throw new EIDASSAMLEngineException(iae);
        } catch (NoSuchFieldException nsfe) {
            throw new EIDASSAMLEngineException(nsfe);
        }
    }

    public void addIDPRole() throws EIDASSAMLEngineException {
        try {
            if (idpSSODescriptor == null) {
                idpSSODescriptor = BuilderFactoryUtil.buildXmlObject(IDPSSODescriptor.class);
            }
        } catch (IllegalAccessException iae) {
            throw new EIDASSAMLEngineException(iae);
        } catch (NoSuchFieldException nsfe) {
            throw new EIDASSAMLEngineException(nsfe);
        }
    }

    private void generateDigest(Extensions eidasExtensions) throws EIDASSAMLEngineException {
        if (!StringUtils.isEmpty(params.getDigestMethods())) {
            Set<String> signatureMethods = EIDASUtil.parseSemicolonSeparatedList(params.getDigestMethods());
            Set<String> digestMethods = new HashSet<String>();
            for (String signatureMethod : signatureMethods) {
                digestMethods.add(CertificateUtil.validateDigestAlgorithm(signatureMethod));
            }
            for (String digestMethod : digestMethods) {
                final DigestMethod dm = (DigestMethod) BuilderFactoryUtil.buildXmlObject(DigestMethod.DEF_ELEMENT_NAME);
                if (dm != null) {
                    dm.setAlgorithm(digestMethod);
                    eidasExtensions.getUnknownXMLObjects().add(dm);
                } else {
                    LOGGER.info("BUSINESS EXCEPTION error adding DigestMethod extension");
                }
            }
        }

    }

    private Extensions generateExtensions() throws EIDASSAMLEngineException {
        Extensions eidasExtensions = BuilderFactoryUtil.generateMetadataExtension();
        if (params.assuranceLevel != null) {
            generateLoA(eidasExtensions);
        }
        if (!StringUtils.isEmpty(params.getSpType())) {
            final SPType spTypeObj = (SPType) BuilderFactoryUtil.buildXmlObject(SPType.DEF_ELEMENT_NAME);
            if (spTypeObj != null) {
                spTypeObj.setSPType(params.getSpType());
                eidasExtensions.getUnknownXMLObjects().add(spTypeObj);
            } else {
                LOGGER.info("BUSINESS EXCEPTION error adding SPType extension");
            }
        }
        generateDigest(eidasExtensions);

        if (!StringUtils.isEmpty(params.getSigningMethods())) {
            Set<String> signMethods = EIDASUtil.parseSemicolonSeparatedList(params.getDigestMethods());
            for (String signMethod : signMethods) {
                final SigningMethod sm =
                        (SigningMethod) BuilderFactoryUtil.buildXmlObject(SigningMethod.DEF_ELEMENT_NAME);
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

    private void generateLoA(Extensions eidasExtensions) throws EIDASSAMLEngineException {
        EntityAttributes loa =
                (EntityAttributes) BuilderFactoryUtil.buildXmlObject(EntityAttributes.DEFAULT_ELEMENT_NAME);
        Attribute loaAttrib = (Attribute) BuilderFactoryUtil.buildXmlObject(Attribute.DEFAULT_ELEMENT_NAME);
        loaAttrib.setName(EidasConstants.LEVEL_OF_ASSURANCE_NAME);
        loaAttrib.setNameFormat(Attribute.URI_REFERENCE);
        XSStringBuilder stringBuilder =
                (XSStringBuilder) Configuration.getBuilderFactory().getBuilder(XSString.TYPE_NAME);
        XSString stringValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
        stringValue.setValue(params.assuranceLevel);
        loaAttrib.getAttributeValues().add(stringValue);
        loa.getAttributes().add(loaAttrib);
        eidasExtensions.getUnknownXMLObjects().add(loa);

    }

    private void addAssertionConsumerService() throws EIDASSAMLEngineException {
        int index = 0;
        Set<String> bindings = params.getProtocolBinding().isEmpty() ? DEFAULT_BINDING : params.getProtocolBinding();
        for (String binding : bindings) {
            AssertionConsumerService asc = (AssertionConsumerService) BuilderFactoryUtil.buildXmlObject(
                    AssertionConsumerService.DEFAULT_ELEMENT_NAME);
            asc.setLocation(params.assertionConsumerUrl);
            asc.setBinding(checkBinding(binding));
            asc.setIndex(index);
            if (index == 0) {
                asc.setIsDefault(true);
            }
            index++;
            spSSODescriptor.getAssertionConsumerServices().add(asc);
        }
    }

    private String checkBinding(String binding) {
        if (binding != null && (binding.equals(SAMLConstants.SAML2_REDIRECT_BINDING_URI) || binding.equals(
                SAMLConstants.SAML2_POST_BINDING_URI))) {
            return binding;
        }
        return SAMLConstants.SAML2_POST_BINDING_URI;
    }

    private DateTime getExpireDate() {
        DateTime expiryDate = DateTime.now();
        expiryDate =
                expiryDate.withFieldAdded(DurationFieldType.seconds(), (int) (getConfigParams().getValidityDuration()));
        return expiryDate;
    }

    private void generateSupportedAttributes(IDPSSODescriptor idpssoDescriptor,
                                             ImmutableSortedSet<AttributeDefinition<?>> attributeDefinitions)
            throws EIDASSAMLEngineException {
        List<Attribute> attributes = idpssoDescriptor.getAttributes();
        for (AttributeDefinition<?> attributeDefinition : attributeDefinitions) {
            Attribute a = (Attribute) BuilderFactoryUtil.buildXmlObject(Attribute.DEFAULT_ELEMENT_NAME);
            a.setName(attributeDefinition.getNameUri().toASCIIString());
            a.setFriendlyName(attributeDefinition.getFriendlyName());
            a.setNameFormat(Attribute.URI_REFERENCE);
            attributes.add(a);
        }
    }

    public MetadataConfigParams getConfigParams() {
        return params;
    }

    public void setConfigParams(MetadataConfigParams params) {
        this.params = params;
    }

    public String[][] getContactStrings() {
        return CONTACTS;
    }
}
