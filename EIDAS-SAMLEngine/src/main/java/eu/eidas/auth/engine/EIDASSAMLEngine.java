/*
 * Licensed under the EUPL, Version 1.1 or - as soon they will be approved by
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

package eu.eidas.auth.engine;

import eu.eidas.auth.commons.*;
import eu.eidas.auth.engine.core.*;
import eu.eidas.auth.engine.core.eidas.EidasExtensionProcessor;
import eu.eidas.auth.engine.core.eidas.GenericEidasAttributeType;
import eu.eidas.auth.engine.core.stork.QAAAttribute;
import eu.eidas.auth.engine.core.stork.StorkExtensionProcessor;
import eu.eidas.auth.engine.core.validator.STORKAttributes;
import eu.eidas.auth.engine.core.validator.eidas.EIDASAttributes;
import eu.eidas.configuration.SAMLBootstrap;
import eu.eidas.engine.exceptions.SAMLEngineException;
import eu.eidas.engine.exceptions.EIDASSAMLEngineException;
import eu.eidas.samlengineconfig.CertificateConfigurationManager;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.common.xml.SAMLSchemaBuilder;
import org.opensaml.saml2.common.Extensions;
import org.opensaml.saml2.core.*;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.Namespace;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.impl.*;
import org.opensaml.xml.security.BasicSecurityConfiguration;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.validation.ValidationException;
import org.opensaml.xml.validation.ValidatorSuite;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import javax.xml.namespace.QName;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import java.io.*;
import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Class that wraps the operations over SAML tokens, both generation and
 * validation of SAML EIDAS requests and SAML EIDAS responses. Complaint with
 * "OASIS Secure Assertion Markup Language (SAML) 2.0, May 2005", but taking
 * into account EIDAS (and other supported formats) specific requirements.
 * 
 * @author fjquevedo
 * @author iinigo
 */
public final class EIDASSAMLEngine extends AbstractSAMLEngine {

	/** The Constant LOG. */
	private static final Logger LOG = LoggerFactory.getLogger(EIDASSAMLEngine.class.getName());
    private static final int HEXA=16;
    private static final String EIDAS_NATURALPERSON_IDENTIFIER="http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier";
    private static final String EIDAS_LEGALPERSON_IDENTIFIER="http://eidas.europa.eu/attributes/legalperson/LegalPersonIdentifier";
	private static final String VALIDATION_MESSAGE_SEPARATOR=", ";
	private static final String UNIQUE_ID_POSTFIX = "/uniqueid";

    private SAMLEngineClock clock;

    /**
     * Allows overriding system clock for testing purposes.
     *
     * @param clock the SAMLEngineClock to be used
     */
    public void setClock(SAMLEngineClock clock) {
        this.clock = clock;
    }

    public static final String ATTRIBUTE_EMPTY_LITERAL = "Attribute name is null or empty.";


    /**
     * Creates an instance of EIDASSAMLEngine.
     *
     * @param nameInstance the name instance
     * @return instance of EIDASSAMLEngine
     */
    public static synchronized EIDASSAMLEngine createSAMLEngine(final String nameInstance) throws EIDASSAMLEngineException{
        return createSAMLEngine(nameInstance, null);
    }

	public static synchronized EIDASSAMLEngine createSAMLEngine(final String nameInstance, CertificateConfigurationManager configManager) throws EIDASSAMLEngineException{
		EIDASSAMLEngine engine = null;
		LOG.info(SAML_EXCHANGE, "Get instance: {} ", nameInstance);
		try {
			engine = new EIDASSAMLEngine(nameInstance.trim(), configManager);
		} catch (EIDASSAMLEngineException e) {
			throw e;
		} catch (Exception e) {
			LOG.error("Error get instance: " + nameInstance+ " {}", e);
		}
		return engine;
	}

	private static AtomicLong counter = new AtomicLong(0);
    private long id;
	private EIDASSAMLEngine(final String nameInstance, final CertificateConfigurationManager configManager) throws EIDASSAMLEngineException, ConfigurationException  {
		this(nameInstance, DEFAULT_CONFIG_NAME, configManager);
	}
	/**
	 * Instantiate a new EIDASSAML engine.
	 * 
	 * @param nameInstance the name instance
	 * 
	 * @throws EIDASSAMLEngineException the EIDASSAML engine exception
	 */
	private EIDASSAMLEngine(final String nameInstance, final String configName, final CertificateConfigurationManager configManager) throws EIDASSAMLEngineException, ConfigurationException  {
		// Initialization OpenSAML.
		super(nameInstance, configName, configManager);
        id=counter.incrementAndGet();
		LOG.trace("Register EIDAS objects provider.");
		Configuration.registerObjectProvider(XSAny.TYPE_NAME,
				new XSAnyBuilder(), new XSAnyMarshaller(),
				new XSAnyUnmarshaller());

		SAMLBootstrap.bootstrap();

        // Registering a new system clock
        this.setClock(new SAMLEngineSystemClock());
        setDigestMethodAlgorithm(null);
	}

    @Override
    public int hashCode(){
        return (int)(id%97);
    }
    @Override
    public boolean equals(Object obj){
        if(obj instanceof EIDASSAMLEngine){
            return id==((EIDASSAMLEngine)obj).id;
        }
        return false;
    }
    public void setDigestMethodAlgorithm(String algorithm){
        BasicSecurityConfiguration config=SAMLEngineUtils.getEidasGlobalSecurityConfiguration();
        if(config!=null && StringUtils.isNotBlank(algorithm)) {
			config.setSignatureReferenceDigestMethod(SAMLEngineUtils.validateDigestAlgorithm(algorithm));
		} else{
			LOG.error("Configuration error - Unable to set DigestMethodAlgorithm - config {} algorithm {} not set", config, algorithm);
		}
    }
	/**
	 * Generate authentication response base.
	 * 
	 * @param status the status
	 * @param assertConsumerURL the assert consumer URL.
	 * @param inResponseTo the in response to
	 * 
	 * @return the response
	 * 
	 * @throws EIDASSAMLEngineException the EIDASSAML engine exception
	 */
	private Response genAuthnRespBase(final Status status,
			final String assertConsumerURL, final String inResponseTo)
	throws EIDASSAMLEngineException {
		LOG.debug("Generate Authentication Response base.");
		final Response response = SAMLEngineUtils.generateResponse(
				SAMLEngineUtils.generateNCName(),
				SAMLEngineUtils.getCurrentTime(), status);

		// Set name Spaces
		this.setResponseNameSpaces(response);

		// Mandatory EIDAS
		LOG.debug("Generate Issuer");
		final Issuer issuer = SAMLEngineUtils.generateIssuer();
		issuer.setValue(super.getSamlCoreProperties().getResponder());

		// Format Entity Optional EIDAS
		issuer.setFormat(super.getSamlCoreProperties().getFormatEntity());

		response.setIssuer(issuer);

		// destination Mandatory EIDAS
		if(assertConsumerURL!=null) {
			response.setDestination(assertConsumerURL.trim());
		}

		// inResponseTo Mandatory 
		response.setInResponseTo(inResponseTo.trim());

		// Optional
		response.setConsent(super.getSamlCoreProperties()
				.getConsentAuthnResponse());

		return response;
	}

	/**
	 * Generate assertion.
	 * 
	 * @param ipAddress the IP address.
	 * @param request the request for which the response is prepared
	 * @param notOnOrAfter the not on or after
	 * 
	 * @return the assertion
	 * 
	 * @throws EIDASSAMLEngineException the EIDASSAML engine exception
	 */
	private Assertion generateAssertion(final String ipAddress,
			final EIDASAuthnRequest request, Response response, IPersonalAttributeList pal, final DateTime notOnOrAfter)
	throws EIDASSAMLEngineException {
		LOG.trace("Generate Assertion.");

		// Mandatory 
		LOG.trace("Generate Issuer to Assertion");
		final Issuer issuerAssertion = SAMLEngineUtils.generateIssuer();
		issuerAssertion.setValue(response.getIssuer().getValue());

		// Format Entity Optional 
		issuerAssertion.setFormat(super.getSamlCoreProperties().getFormatEntity());

		final Assertion assertion = SAMLEngineUtils.generateAssertion(
				SAMLVersion.VERSION_20, SAMLEngineUtils.generateNCName(),
				SAMLEngineUtils.getCurrentTime(), issuerAssertion);

		final Subject subject = SAMLEngineUtils.generateSubject();

		// Mandatory to be verified
		// String format = NameID.UNSPECIFIED
		// specification: 'SAML:2.0' exist
		// opensaml: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
		// opensaml  "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified"
		String format =request.getEidasNameidFormat();
		if(format==null) {
			format = SAMLExtensionFormat.EIDAS10 == getExtensionProcessor().getFormat() ? EIDASAuthnRequest.NAMEID_FORMAT_PERSISTENT :EIDASAuthnRequest.NAMEID_FORMAT_UNSPECIFIED;
		}

		final String nameQualifier = "";

		LOG.trace("Generate NameID");
		final NameID nameId = SAMLEngineUtils.generateNameID(super
				.getSamlCoreProperties().getResponder(), format, nameQualifier);
        String nameIdValue=getUniquenessIdentifier(request, pal);
		nameId.setValue(nameIdValue);
		subject.setNameID(nameId);

		// Mandatory if urn:oasis:names:tc:SAML:2.0:cm:bearer.
		// Optional in other case.
		LOG.trace("Generate SubjectConfirmationData.");
		final SubjectConfirmationData dataBearer = SAMLEngineUtils
		.generateSubjectConfirmationData(SAMLEngineUtils
				.getCurrentTime(), request.getAssertionConsumerServiceURL(), request.getSamlId());

		// Mandatory if urn:oasis:names:tc:SAML:2.0:cm:bearer.
		// Optional in other case.
		LOG.trace("Generate SubjectConfirmation");
		final SubjectConfirmation subjectConf = SAMLEngineUtils
		.generateSubjectConfirmation(SubjectConfirmation.METHOD_BEARER,
				dataBearer);

		final List<SubjectConfirmation> listSubjectConf = new ArrayList<SubjectConfirmation>();
		listSubjectConf.add(subjectConf);

		for (final Iterator<SubjectConfirmation> iter = listSubjectConf
				.iterator(); iter.hasNext();) {
			final SubjectConfirmation element = iter.next();

			if (SubjectConfirmation.METHOD_BEARER.equals(element.getMethod())) {
				// ipAddress Mandatory if method is Bearer.

				if (StringUtils.isBlank(ipAddress)) {
					LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : ipAddress is null or empty");
					throw new EIDASSAMLEngineException(EIDASErrors.INTERNAL_ERROR.errorCode(),
                            EIDASErrors.INTERNAL_ERROR.errorCode(),"ipAddress is null or empty");
				}
				element.getSubjectConfirmationData().setAddress(ipAddress.trim());
			}

			element.getSubjectConfirmationData().setRecipient(request.getAssertionConsumerServiceURL());
			element.getSubjectConfirmationData().setNotOnOrAfter(notOnOrAfter);
		}

		// The SAML 2.0 specification allows multiple SubjectConfirmations
		subject.getSubjectConfirmations().addAll(listSubjectConf);

		// Mandatory 
		assertion.setSubject(subject);

		// Conditions that MUST be evaluated when assessing the validity of
		// and/or when using the assertion.
		final Conditions conditions = this.generateConditions(SAMLEngineUtils.getCurrentTime(), notOnOrAfter, request.getIssuer());

		assertion.setConditions(conditions);

		LOG.trace("Generate Authentication Statement.");
		final AuthnStatement eidasAuthnStat = this.generateAuthStatement(ipAddress);
		assertion.getAuthnStatements().add(eidasAuthnStat);

		return assertion;
	}

    private String getUniquenessIdentifier (final EIDASAuthnRequest request, IPersonalAttributeList pal) throws EIDASSAMLEngineException{
        for (PersonalAttribute attribute : pal) {

            String attributeName = getAttributeName(attribute);
            if(EIDAS_NATURALPERSON_IDENTIFIER.equals(attributeName) && !attribute.isEmptyValue()){
                return attribute.getValue().get(0);
            }
            if(EIDAS_LEGALPERSON_IDENTIFIER.equals(attributeName) && !attribute.isEmptyValue()){
                return attribute.getValue().get(0);
            }
        }
        return request.getCountry()+UNIQUE_ID_POSTFIX;
    }

    private String getAttributeName(final PersonalAttribute attribute) throws EIDASSAMLEngineException {
        if (StringUtils.isBlank(attribute.getName())) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : {}", ATTRIBUTE_EMPTY_LITERAL);
            throw new EIDASSAMLEngineException(ATTRIBUTE_EMPTY_LITERAL);
        }

        final String attributeName = extensionProcessor.getAttributeFullName(this, attribute.getName());

        if (StringUtils.isBlank(attributeName)) {
            LOG.info("BUSINESS EXCEPTION : Attribute name: {} it is not known.", attribute.getName());
            throw new EIDASSAMLEngineException(EIDASErrors.INTERNAL_ERROR.errorCode(),
                    EIDASErrors.INTERNAL_ERROR.errorCode(),"Attribute name: " + attribute.getName() + " it is not known.");
        }
        return attributeName;
    }
	/**
	 * Generate attribute statement.
	 * 
	 * @param personalAttrList the personal attribute list
	 * @param isHashing the is hashing
	 * 
	 * @return the attribute statement
	 * 
	 * @throws EIDASSAMLEngineException the SAML engine exception
	 * @throws IOException
	 */
	private AttributeStatement generateAttributeStatement(
			final IPersonalAttributeList personalAttrList,
			final boolean isHashing) throws EIDASSAMLEngineException {
		LOG.trace("Generate attribute statement");

		final AttributeStatement attrStatement = (AttributeStatement) SAMLEngineUtils
		.createSamlObject(AttributeStatement.DEFAULT_ELEMENT_NAME);
        final List<Attribute> list=attrStatement.getAttributes();
        if(extensionProcessor==null){
            return null;
        }

		for (PersonalAttribute attribute : personalAttrList) {


			// Verification that only one value it's permitted, simple or
			// complex, not both.

			final boolean simpleEmpty = attribute.getValue() == null || attribute.getValue().isEmpty();

			final boolean complexEmpty = attribute.getComplexValue() == null || attribute.getComplexValue().isEmpty();
			setAttributeValues(attribute, list, simpleEmpty, complexEmpty, isHashing);
		}
		return attrStatement;
	}

	private void setAttributeValues(final PersonalAttribute attribute, List<Attribute> list,
									boolean simpleEmpty, boolean complexEmpty,final boolean isHashing)throws EIDASSAMLEngineException {
		String attributeName = getAttributeName(attribute);
		if (!simpleEmpty && !complexEmpty) {
			throw new EIDASSAMLEngineException(EIDASErrors.INTERNAL_ERROR.errorCode(),
					EIDASErrors.INTERNAL_ERROR.errorCode(),
					"Attribute name: " + attribute.getName() + " must be contain one value, simple or complex value.");
		} else {

			if (!simpleEmpty) {
				list.add(
						extensionProcessor.generateAttrSimple(attributeName, attribute
										.getStatus(), attribute.getValue(), isHashing));
			} else if (!complexEmpty) {
				list.add(
						SAMLEngineUtils.generateAttrComplex(this, attributeName,
								attribute.getStatus(), attribute
										.getComplexValue(), isHashing));
			} else if (attribute.getValue()!=null) {
				list.add(
						extensionProcessor.generateAttrSimple(attributeName, attribute
										.getStatus(), new ArrayList<String>(),isHashing));
			} else {
				// Add attribute complex.
				list.add(
						SAMLEngineUtils.generateAttrComplex(this, attributeName,
								attribute.getStatus(),
								new HashMap<String, String>(), isHashing));
			}
		}
	}

    static CharsetEncoder encoder = Charset.forName("ISO-8859-1").newEncoder();

    public static boolean needsTransliteration(String v) {
        return !encoder.canEncode(v);
    }



	/**
	 * Generate conditions that MUST be evaluated when assessing the validity of
	 * and/or when using the assertion.
	 * 
	 * @param notBefore the not before
	 * @param notOnOrAfter the not on or after
	 * @param audienceURI the audience URI.
	 * 
	 * @return the conditions
	 */
	private Conditions generateConditions(final DateTime notBefore,
			final DateTime notOnOrAfter, final String audienceURI) {
		LOG.trace("Generate conditions.");
		final Conditions conditions = (Conditions) SAMLEngineUtils
		.createSamlObject(Conditions.DEFAULT_ELEMENT_NAME);
		conditions.setNotBefore(notBefore);
		conditions.setNotOnOrAfter(notOnOrAfter);

		final AudienceRestriction restrictions = (AudienceRestriction) SAMLEngineUtils
		.createSamlObject(AudienceRestriction.DEFAULT_ELEMENT_NAME);

		final Audience audience = (Audience) SAMLEngineUtils
		.createSamlObject(Audience.DEFAULT_ELEMENT_NAME);
		audience.setAudienceURI(audienceURI);

		restrictions.getAudiences().add(audience);
		conditions.getAudienceRestrictions().add(restrictions);

		if (super.getSamlCoreProperties().isOneTimeUse()) {
			final OneTimeUse oneTimeUse = (OneTimeUse) SAMLEngineUtils
			.createSamlObject(OneTimeUse.DEFAULT_ELEMENT_NAME);
			conditions.getConditions().add(oneTimeUse);
		}
		return conditions;
	}


    private AttributeStatement findAttributeStatement(final Assertion assertion) throws EIDASSAMLEngineException{
        final List<XMLObject> listExtensions = assertion.getOrderedChildren();
        boolean find = false;
        AttributeStatement requestedAttr = null;

        // Search the attribute statement.
        for (int i = 0; i < listExtensions.size() && !find; i++) {
            final XMLObject xml = listExtensions.get(i);
            if (xml instanceof AttributeStatement) {
                requestedAttr = (AttributeStatement) xml;
                find = true;
            }
        }

        if (!find) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : AttributeStatement it's not present.");
            throw new EIDASSAMLEngineException(EIDASErrors.INTERNAL_ERROR.errorCode(),
                    EIDASErrors.INTERNAL_ERROR.errorCode(),"AttributeStatement it's not present.");
        }
        return requestedAttr;

    }
    private String computeSimpleValue(XSAnyImpl xmlString){
        TransformerFactory transFactory = TransformerFactory
                .newInstance();
        Transformer transformer = null;
        try {
            transformer = transFactory.newTransformer();
            transformer.setOutputProperty(
                    OutputKeys.OMIT_XML_DECLARATION, "yes");
        } catch (TransformerConfigurationException e) {
            LOG.warn(SAML_EXCHANGE, "ERROR : transformer configuration exception", e);
        }
        StringWriter buffer = new StringWriter();
        try {
            if (transformer!= null && xmlString != null && xmlString.getUnknownXMLObjects() != null && !xmlString.getUnknownXMLObjects().isEmpty() ){
                transformer.transform(new DOMSource(xmlString
                                .getUnknownXMLObjects().get(0).getDOM()),
                        new StreamResult(buffer));
            }
        } catch (TransformerException e) {
            LOG.warn(SAML_EXCHANGE, "ERROR :  transformer exception", e);
        }
        return buffer.toString();
    }

    private Map<String, String> computeComplexValue(final XSAnyImpl complexValue){
        final Map<String, String> multiValues = new HashMap<String, String>();
        for (int nextComplexValue = 0; nextComplexValue < complexValue
                .getUnknownXMLObjects().size(); nextComplexValue++) {

            final XSAnyImpl simple = (XSAnyImpl) complexValue
                    .getUnknownXMLObjects().get(
                            nextComplexValue);

            multiValues.put(simple.getElementQName()
                    .getLocalPart(), simple.getTextContent());
        }
        return multiValues;

    }
	/**
	 * Generate personal attribute list.
	 * 
	 * @param assertion the assertion
	 * 
	 * @return the personal attribute list
	 * 
	 * @throws EIDASSAMLEngineException the SAML engine exception
	 */
	private IPersonalAttributeList generatePersonalAttributeList(
			final Assertion assertion) throws EIDASSAMLEngineException {
		LOG.trace("Generate personal attribute list from XMLObject.");

        AttributeStatement requestedAttr =findAttributeStatement(assertion);

        final List<Attribute> reqAttrs = requestedAttr.getAttributes();

		final IPersonalAttributeList personalAttrList = new PersonalAttributeList();
		String attributeName;

		// Process the attributes.
		for (int nextAttribute = 0; nextAttribute < reqAttrs.size(); nextAttribute++) {
			final Attribute attribute = reqAttrs.get(nextAttribute);

			final PersonalAttribute personalAttribute = new PersonalAttribute();

			attributeName = attribute.getName();
			personalAttribute.setName(attributeName.substring(attributeName
					.lastIndexOf('/') + 1));

			personalAttribute.setStatus(attribute.getUnknownAttributes().get(
					new QName(getExtensionProcessor().getFormat().getAssertionNS(), "AttributeStatus",
							getExtensionProcessor().getFormat().getAssertionPrefix())));

			final List<String> simpleValues = new ArrayList<String>();
			final Map<String, String> multiValues = new HashMap<String, String>();

			final List<XMLObject> values = attribute.getOrderedChildren();
			
						
			// Process the values.
			for (int nextValue = 0; nextValue < values.size(); nextValue++) {

				final XMLObject xmlObject = values.get(nextValue);

				if (xmlObject instanceof XSStringImpl) {

					// Process simple value.
					simpleValues.add(((XSStringImpl) xmlObject).getValue());

				} else if (xmlObject instanceof XSAnyImpl) {

					if ("http://www.stork.gov.eu/1.0/signedDoc"
							.equals(attributeName)) {

						final XSAnyImpl xmlString = (XSAnyImpl) values
								.get(nextValue);
                        simpleValues.add(computeSimpleValue(xmlString));

					} else if ("http://www.stork.gov.eu/1.0/canonicalResidenceAddress"
							.equals(attributeName)) {

						// Process complex value.
						final XSAnyImpl complexValue = (XSAnyImpl) xmlObject;
                        multiValues.putAll(computeComplexValue(complexValue));
					} else {
						// Process simple value.
						simpleValues.add(((XSAnyImpl) xmlObject).getTextContent());
					}

				} else if (xmlObject instanceof GenericEidasAttributeType) {

					// Process simple value.
					simpleValues.add(((GenericEidasAttributeType) xmlObject).getValue());

				} else {
					LOG.info("BUSINESS EXCEPTION : attribute value is unknown in generatePersonalAttributeList.");
					throw new EIDASSAMLEngineException(EIDASErrors.INTERNAL_ERROR.errorCode(),
                            EIDASErrors.INTERNAL_ERROR.errorCode(),"Attribute value it's unknown.");
				}
			}

			personalAttribute.setValue(simpleValues);
			personalAttribute.setComplexValue(multiValues);
			personalAttrList.add(personalAttribute);
		}

		return personalAttrList;
	}

	/**
	 * Generate the authentication request.
	 * 
	 * @param request the request that contain all parameters for generate an
	 *            authentication request.
	 * 
	 * @return the EIDAS authentication request that has been processed.
	 * 
	 * @throws EIDASSAMLEngineException the EIDASSAML engine exception
	 */
	public EIDASAuthnRequest generateEIDASAuthnRequest(
			final EIDASAuthnRequest request) throws EIDASSAMLEngineException {
		LOG.trace("Generate SAMLAuthnRequest.");
		if(request ==null){
			LOG.debug(SAML_EXCHANGE, "Sign and Marshall - null input");
			LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : Sign and Marshall -null input");
			throw new EIDASSAMLEngineException(
					EIDASErrors.INTERNAL_ERROR.errorCode(),
					EIDASErrors.INTERNAL_ERROR.errorMessage());
		}
        selectFormat(request.getMessageFormatName());
        // Validate Parameters mandatories
		validateParamAuthnReq(request);

		final AuthnRequest authnRequestAux = SAMLEngineUtils
                .generateSAMLAuthnRequest(SAMLEngineUtils.generateNCName(),
                        SAMLVersion.VERSION_20, SAMLEngineUtils.getCurrentTime());

		// Set name spaces.
		setRequestNameSpaces(authnRequestAux);

		// Add parameter Mandatory
		authnRequestAux.setForceAuthn(Boolean.TRUE);

		// Add parameter Mandatory 
		authnRequestAux.setIsPassive(Boolean.FALSE);

		authnRequestAux.setAssertionConsumerServiceURL(request.getAssertionConsumerServiceURL());

		authnRequestAux.setProviderName(request.getProviderName());

		// Add protocol binding
		authnRequestAux.setProtocolBinding(getProtocolBinding(request.getBinding()));

		// Add parameter optional 
		// Destination is mandatory 
		// The application must to know the destination
		if (StringUtils.isNotBlank(request.getDestination())) {
			authnRequestAux.setDestination(request.getDestination());
		}

		// Consent is optional. Set from SAMLEngine.xml - consent.
		authnRequestAux.setConsent(super.getSamlCoreProperties()
				.getConsentAuthnRequest());

		final Issuer issuer = SAMLEngineUtils.generateIssuer();
		
		if(request.getIssuer()!=null){
			issuer.setValue(SAMLEngineUtils.getValidIssuerValue(request.getIssuer()));
        } else {
			issuer.setValue(super.getSamlCoreProperties().getRequester());
        }

		// Optional 
		final String formatEntity = super.getSamlCoreProperties().getFormatEntity();
		if (StringUtils.isNotBlank(formatEntity)) {
			issuer.setFormat(formatEntity);
		}

		authnRequestAux.setIssuer(issuer);
		addAuthnContext(request, authnRequestAux);

		// Generate format extensions.
		final Extensions formatExtensions =getExtensionProcessor().generateExtensions(this, request);
		// add the extensions to the SAMLAuthnRequest
		authnRequestAux.setExtensions(formatExtensions);
		addNameIDPolicy(authnRequestAux, request.getEidasNameidFormat());

		// the result contains an authentication request token (byte[]),
		// identifier of the token, and all parameters from the request.
		final EIDASAuthnRequest authRequest = getExtensionProcessor().processExtensions(authnRequestAux
				.getExtensions());
        authRequest.setMessageFormatName(getExtensionProcessor().getFormat().getName());

		try {
			authRequest.setTokenSaml(super.signAndMarshall(authnRequestAux, getExtensionProcessor().getFormat().getName()));
		} catch (SAMLEngineException e) {
			LOG.debug(SAML_EXCHANGE, "Sign and Marshall.", e);
			LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : Sign and Marshall.", e);
			throw new EIDASSAMLEngineException(
					EIDASErrors.INTERNAL_ERROR.errorCode(),
					EIDASErrors.INTERNAL_ERROR.errorMessage(), e);
		}

		authRequest.setSamlId(authnRequestAux.getID());
		authRequest.setDestination(authnRequestAux.getDestination());
		authRequest.setAssertionConsumerServiceURL(authnRequestAux
				.getAssertionConsumerServiceURL());

		authRequest.setProviderName(authnRequestAux.getProviderName());
		authRequest.setIssuer(authnRequestAux.getIssuer().getValue());
        authRequest.setBinding(request.getBinding());
		authRequest.setOriginalIssuer(request.getOriginalIssuer());
        authRequest.setEidasLoACompareType(request.getEidasLoACompareType());
        authRequest.setEidasLoA(request.getEidasLoA());
		authRequest.setEidasNameidFormat(request.getEidasNameidFormat());

		return authRequest;
	}

    private void selectFormat( String selectedFormat){
        if(!StringUtils.isEmpty(selectedFormat) && SAMLExtensionFormat.AVAILABLE_FORMATS.containsKey(selectedFormat)){
            for(ExtensionProcessorI proc:availableExtensionProcessors){
                if(proc.getFormat()==SAMLExtensionFormat.AVAILABLE_FORMATS.get(selectedFormat)){
                    setExtensionProcessor(proc);
                    break;
                }
            }
        }
    }

    private void addNameIDPolicy(final AuthnRequest authnRequestAux, final String selectedNameID) {
		if (extensionProcessor != null && extensionProcessor.getFormat() == SAMLExtensionFormat.EIDAS10 && !StringUtils.isEmpty(selectedNameID)) {
			NameIDPolicy policy = (NameIDPolicy) SAMLEngineUtils.createSamlObject(NameIDPolicy.DEFAULT_ELEMENT_NAME);
			policy.setFormat(selectedNameID);
			policy.setAllowCreate(true);
			authnRequestAux.setNameIDPolicy(policy);
		}
	}

	private void addAuthnContext(final EIDASAuthnRequest request, AuthnRequest authnRequestAux) throws EIDASSAMLEngineException{
		if(StringUtils.isEmpty(request.getEidasLoA())) {
			return;
		}
		if( EidasLoaLevels.getLevel(request.getEidasLoA())==null){
			throw new EIDASSAMLEngineException(EIDASErrors.COLLEAGUE_REQ_INVALID_LOA.errorCode(), EIDASErrors.COLLEAGUE_REQ_INVALID_LOA.errorMessage());
		}
		RequestedAuthnContext authnContext = (RequestedAuthnContext)SAMLEngineUtils.createSamlObject(RequestedAuthnContext.DEFAULT_ELEMENT_NAME);
		authnContext.setComparison(SAMLEngineUtils.getAuthnCtxtComparisonType(EidasLoaCompareType.getCompareType(request.getEidasLoACompareType())));
		AuthnContextClassRef authnContextClassRef = (AuthnContextClassRef)SAMLEngineUtils.createSamlObject(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
		authnContextClassRef.setAuthnContextClassRef(request.getEidasLoA());
		authnContext.getAuthnContextClassRefs().add(authnContextClassRef);
		authnRequestAux.setRequestedAuthnContext(authnContext);

	}
    public EIDASAuthnResponse generateEIDASAuthnResponse(
            final EIDASAuthnRequest request,
            final EIDASAuthnResponse responseAuthReq, final String ipAddress,
            final boolean isHashing) throws EIDASSAMLEngineException {
        return generateEIDASAuthnResponse(request, responseAuthReq, ipAddress,isHashing,false);
    }
	/**
	 * Generate authentication response in one of the supported formats.
	 * 
	 * @param request the request
	 * @param responseAuthReq the response authentication request
	 * @param ipAddress the IP address
     * @param isHashing the is hashing
     * @param signAssertion whether to sign the attribute assertion
	 *
	 * @return the authentication response
	 * 
	 * @throws EIDASSAMLEngineException the EIDASSAML engine exception
	 */
	public EIDASAuthnResponse generateEIDASAuthnResponse(
			final EIDASAuthnRequest request,
			final EIDASAuthnResponse responseAuthReq, final String ipAddress,
			final boolean isHashing, final boolean signAssertion) throws EIDASSAMLEngineException {
		LOG.trace("generateEIDASAuthnResponse");
        //if not setted before
		if(StringUtils.isEmpty(getCountryRespondTo())) {
			setCountryRespondTo(request.getCountry());
		}

		// Validate parameters
		validateParamResponse(request, responseAuthReq);

		// Mandatory SAML
		LOG.trace("Generate StatusCode");
		final StatusCode statusCode = SAMLEngineUtils
		.generateStatusCode(StatusCode.SUCCESS_URI);

		LOG.trace("Generate Status");
		final Status status = SAMLEngineUtils.generateStatus(statusCode);

		LOG.trace("Generate StatusMessage");
		final StatusMessage statusMessage = (StatusMessage) SAMLEngineUtils
		.generateStatusMessage(StatusCode.SUCCESS_URI);

		status.setStatusMessage(statusMessage);

		LOG.trace("Generate Response");

		// RESPONSE
		final Response response = genAuthnRespBase(status, request
				.getAssertionConsumerServiceURL(), request.getSamlId());

		if(responseAuthReq.getIssuer()!=null && !responseAuthReq.getIssuer().isEmpty() && response.getIssuer()!=null){
			response.getIssuer().setValue(SAMLEngineUtils.getValidIssuerValue(responseAuthReq.getIssuer()));
		}
		DateTime notOnOrAfter = new DateTime();

		notOnOrAfter = notOnOrAfter.plusSeconds(super.getSamlCoreProperties()
				.getTimeNotOnOrAfter());

		final Assertion assertion = this.generateAssertion(ipAddress, request, response, responseAuthReq.getPersonalAttributeList(), notOnOrAfter);

		final AttributeStatement attrStatement = this.generateAttributeStatement(responseAuthReq.getPersonalAttributeList(), isHashing);


		assertion.getAttributeStatements().add(attrStatement);
		addAuthnContextClassRef(responseAuthReq,assertion);
		// Add assertions
        Assertion signedAssertion=null;
        if(signAssertion) {
            try {
                signedAssertion = (Assertion) super.sign(assertion, getExtensionProcessor().getFormat().getName());
            }catch(SAMLEngineException exc){
                LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : cannot sign assertion: {}", exc.getMessage());
                LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : cannot sign assertion: {}", exc);
            }
        }
		response.getAssertions().add(signedAssertion==null?assertion:signedAssertion);

		final EIDASAuthnResponse authresponse = new EIDASAuthnResponse();

		try {
			authresponse.setTokenSaml(super.signAndMarshall(response, getExtensionProcessor().getFormat().getName()));
			authresponse.setSamlId(response.getID());
		} catch (SAMLEngineException e) {
			LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : Sign and Marshall.", e.getMessage());
			LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : Sign and Marshall.", e);
			throw new EIDASSAMLEngineException(
					EIDASErrors.INTERNAL_ERROR.errorCode(),
                    EIDASErrors.INTERNAL_ERROR.errorMessage(),e);
		}
		return authresponse;
	}
	private void addAuthnContextClassRef(final EIDASAuthnResponse responseAuthReq,final Assertion assertion){
		if(!StringUtils.isEmpty(responseAuthReq.getAssuranceLevel())) {
			AuthnContextClassRef authnContextClassRef = assertion.getAuthnStatements().get(0).getAuthnContext().getAuthnContextClassRef();
			if(authnContextClassRef==null){
				authnContextClassRef=(AuthnContextClassRef)SAMLEngineUtils.createSamlObject(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
				assertion.getAuthnStatements().get(0).getAuthnContext().setAuthnContextClassRef(authnContextClassRef);
			}
			authnContextClassRef.setAuthnContextClassRef(responseAuthReq.getAssuranceLevel());
		}
	}
	/**
	 * Generate authentication response fail.
	 * 
	 * @param request the request
	 * @param response the response
	 * @param ipAddress the IP address
	 * @param isHashing the is hashing
	 * 
	 * @return the authentication response
	 * 
	 * @throws EIDASSAMLEngineException the EIDASSAML engine exception
	 */
	public EIDASAuthnResponse generateEIDASAuthnResponseFail(
			final EIDASAuthnRequest request, final EIDASAuthnResponse response,
			final String ipAddress, final boolean isHashing)
	throws EIDASSAMLEngineException {
		LOG.trace("generateEIDASAuthnResponseFail");
		if(StringUtils.isEmpty(getCountryRespondTo())) {
			setCountryRespondTo(request.getCountry());
		}

		validateParamResponseFail(request, response);

		// Mandatory
		final StatusCode statusCode = SAMLEngineUtils
		.generateStatusCode(response.getStatusCode());

		// Mandatory SAML
		LOG.trace("Generate StatusCode.");
		// Subordinate code it's optional in case not covered into next codes:
		// - urn:oasis:names:tc:SAML:2.0:status:AuthnFailed
		// - urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue
		// - urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy
		// - urn:oasis:names:tc:SAML:2.0:status:RequestDenied
		// - http://www.stork.gov.eu/saml20/statusCodes/QAANotSupported

		if (StringUtils.isNotBlank(response.getSubStatusCode())) {
			final StatusCode newStatusCode = SAMLEngineUtils
			.generateStatusCode(response.getSubStatusCode());
			statusCode.setStatusCode(newStatusCode);
		}

		LOG.debug("Generate Status.");
		final Status status = SAMLEngineUtils.generateStatus(statusCode);

		if (StringUtils.isNotBlank(response.getMessage())) {
			final StatusMessage statusMessage = (StatusMessage) SAMLEngineUtils
			.generateStatusMessage(response.getMessage());

			status.setStatusMessage(statusMessage);
		}

		LOG.trace("Generate Response.");
		// RESPONSE
		final Response responseFail = genAuthnRespBase(status, request
                .getAssertionConsumerServiceURL(), request.getSamlId());

		if(response.getIssuer()!=null && !response.getIssuer().isEmpty() && response.getIssuer()!=null){
			responseFail.getIssuer().setValue(response.getIssuer());
		}
		DateTime notOnOrAfter = new DateTime();

		notOnOrAfter = notOnOrAfter.plusSeconds(super.getSamlCoreProperties()
				.getTimeNotOnOrAfter());

		final Assertion assertion = this.generateAssertion(ipAddress, request, responseFail, new PersonalAttributeList(),notOnOrAfter);
		addAuthnContextClassRef(response,assertion);
		responseFail.getAssertions().add(assertion);

		LOG.trace("Sign and Marshall ResponseFail.");

		final EIDASAuthnResponse eidasResponse = new EIDASAuthnResponse();

		try {
			eidasResponse.setTokenSaml(super.signAndMarshall(responseFail, getExtensionProcessor().getFormat().getName()));
			eidasResponse.setSamlId(responseFail.getID());
		} catch (SAMLEngineException e) {
			LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : SAMLEngineException.", e.getMessage());
			LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : SAMLEngineException.", e);
			throw new EIDASSAMLEngineException(EIDASErrors.INTERNAL_ERROR.errorCode(),
                    EIDASErrors.INTERNAL_ERROR.errorMessage(),e);
		}
		return eidasResponse;
	}

	/**
	 * Generate authentication statement.
	 * 
	 * @param ipAddress the IP address
	 * 
	 * @return the authentication statement
	 */
	private AuthnStatement generateAuthStatement(final String ipAddress) {
		LOG.trace("Generate authenticate statement.");
		final SubjectLocality subjectLocality = SAMLEngineUtils
		.generateSubjectLocality(ipAddress);

		final AuthnContext authnContext = (AuthnContext) SAMLEngineUtils
		.createSamlObject(AuthnContext.DEFAULT_ELEMENT_NAME);

		final AuthnContextDecl authnContextDecl = (AuthnContextDecl) SAMLEngineUtils
		.createSamlObject(AuthnContextDecl.DEFAULT_ELEMENT_NAME);

		authnContext.setAuthnContextDecl(authnContextDecl);

		final AuthnStatement authnStatement = SAMLEngineUtils
		.generateAthnStatement(new DateTime(), authnContext);

		// Optional 
		authnStatement.setSessionIndex(null);
		authnStatement.setSubjectLocality(subjectLocality);

		return authnStatement;
	}


	/**
	 * Gets the alias from X.509 Certificate at keystore.
	 * 
	 * @param keyInfo the key info
	 * @param ownKeyStore 
	 * @param ownKeyStore 
	 * 
	 * @return the alias
	 */
    private String getAlias(final KeyInfo keyInfo, KeyStore ownKeyStore) {

        LOG.trace("Recover alias information");

        String alias = null;
        try {
            final org.opensaml.xml.signature.X509Certificate xmlCert = keyInfo
                    .getX509Datas().get(0).getX509Certificates().get(0);

            // Transform the KeyInfo to X509Certificate.
            CertificateFactory certFact;
            certFact = CertificateFactory.getInstance("X.509");

            final ByteArrayInputStream bis = new ByteArrayInputStream(Base64.decode(xmlCert.getValue()));

            final X509Certificate cert = (X509Certificate) certFact
                    .generateCertificate(bis);

            final String tokenSerialNumber = cert.getSerialNumber().toString(HEXA);
            final X500Name tokenIssuerDN = new X500Name(cert.getIssuerDN().getName());


            String aliasCert;
            X509Certificate certificate;
            boolean find = false;

            for (final Enumeration<String> e = ownKeyStore.aliases(); e.hasMoreElements() && !find; ) {
                aliasCert = e.nextElement();
                certificate = (X509Certificate) ownKeyStore.getCertificate(aliasCert);

                final String serialNum = certificate.getSerialNumber().toString(HEXA);

				X500Name issuerDN = new X500Name(certificate.getIssuerDN().getName());

                if(serialNum.equalsIgnoreCase(tokenSerialNumber)
                        && X500PrincipalUtil.principalEquals(issuerDN, tokenIssuerDN)){
                    alias = aliasCert;
                    find = true;
                }

            }

        } catch (KeyStoreException e) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : Procces getAlias from certificate associated into the signing keystore: {}", e.getMessage());
            LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : Procces getAlias from certificate associated into the signing keystore: {}", e);
        } catch (CertificateException e) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : Procces getAlias from certificate associated into the signing keystore: {}", e.getMessage());
            LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : Procces getAlias from certificate associated into the signing keystore: {}", e);
        } catch (RuntimeException e) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : Procces getAlias from certificate associated into the signing keystore: {}", e.getMessage());
            LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : Procces getAlias from certificate associated into the signing keystore: {}", e);
        }
        return alias;
    }

	/**
	 * Gets the country from X.509 Certificate.
	 * 
	 * @param keyInfo the key info
	 * 
	 * @return the country
	 */
	private String getCountry(final KeyInfo keyInfo) {
		LOG.trace("Recover country information.");

		String result = "";
		try {
			final org.opensaml.xml.signature.X509Certificate xmlCert = keyInfo
			.getX509Datas().get(0).getX509Certificates().get(0);

			// Transform the KeyInfo to X509Certificate.
			CertificateFactory certFact;
			certFact = CertificateFactory.getInstance("X.509");

			final ByteArrayInputStream bis = new ByteArrayInputStream(Base64
					.decode(xmlCert.getValue()));

			final X509Certificate cert = (X509Certificate) certFact
			.generateCertificate(bis);

			String distName = cert.getSubjectDN().toString();

			distName = StringUtils.deleteWhitespace(StringUtils
					.upperCase(distName));

			final String countryCode = "C=";
			final int init = distName.indexOf(countryCode);

			if (init > StringUtils.INDEX_NOT_FOUND) {
			    // Exist country code.
				int end = distName.indexOf(',', init);

				if (end <= StringUtils.INDEX_NOT_FOUND) {
					end = distName.length();
				}

				if (init < end && end > StringUtils.INDEX_NOT_FOUND) {
					result = distName.substring(init + countryCode.length(),
							end);
					//It must be a two characters value
					if(result.length()>2){
						result = result.substring(0, 2);
                    }
				}
			}

		} catch (CertificateException e) {
			LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : Procces getCountry from certificate. {}", e.getMessage());
			LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : Procces getCountry from certificate. {}", e);
		}
		return result.trim();
	}

	/**
	 * Sets the name spaces. TODO: may be moved to extension processor
	 * 
	 * @param tokenSaml the new name spaces
	 */
	private void setRequestNameSpaces(final XMLObject tokenSaml) {
		LOG.trace("Set namespaces.");
        tokenSaml.getNamespaceManager().registerNamespace(new Namespace(SAMLConstants.SAML20_NS, SAMLConstants.SAML20_PREFIX));
        tokenSaml.getNamespaceManager().registerNamespace(new Namespace("http://www.w3.org/2000/09/xmldsig#", "ds"));
        tokenSaml.getNamespaceManager().registerNamespace(new Namespace(SAMLConstants.SAML20P_NS, SAMLConstants.SAML20P_PREFIX));
		if(this.getExtensionProcessor() instanceof StorkExtensionProcessor) {
			tokenSaml.getNamespaceManager().registerNamespace(new Namespace(SAMLCore.STORK10_NS.getValue(), SAMLCore.STORK10_PREFIX.getValue()));
			tokenSaml.getNamespaceManager().registerNamespace(new Namespace(SAMLCore.STORK10P_NS.getValue(), SAMLCore.STORK10P_PREFIX.getValue()));
		}
		if(this.getExtensionProcessor() instanceof EidasExtensionProcessor) {
			tokenSaml.getNamespaceManager().registerNamespace(new Namespace(SAMLCore.EIDAS10_SAML_NS.getValue(), SAMLCore.EIDAS10_SAML_PREFIX.getValue()));
		}

	}

	/**
	 * Sets the name spaces.
	 *
	 * @param tokenSaml the new name spaces
	 */
	private void setResponseNameSpaces(final XMLObject tokenSaml) {
		LOG.trace("Set namespaces.");
		tokenSaml.getNamespaceManager().registerNamespace(new Namespace(SAMLConstants.SAML20_NS, SAMLConstants.SAML20_PREFIX));
		tokenSaml.getNamespaceManager().registerNamespace(new Namespace("http://www.w3.org/2000/09/xmldsig#", "ds"));
		tokenSaml.getNamespaceManager().registerNamespace(new Namespace(SAMLConstants.SAML20P_NS, SAMLConstants.SAML20P_PREFIX));
		tokenSaml.getNamespaceManager().registerNamespace(new Namespace(SAMLCore.STORK10_NS.getValue(), SAMLCore.STORK10_PREFIX.getValue()));
		tokenSaml.getNamespaceManager().registerNamespace(new Namespace(SAMLCore.STORK10P_NS.getValue(), SAMLCore.STORK10P_PREFIX.getValue()));
		if(this.getExtensionProcessor() instanceof EidasExtensionProcessor) {
			tokenSaml.getNamespaceManager().registerNamespace(new Namespace(SAMLCore.EIDAS10_RESPONSESAML_NS.getValue(), SAMLCore.EIDAS10_SAML_PREFIX.getValue()));
		}

	}

	/**
	 * Validate parameters from authentication request.
	 * 
	 * @param request the request.
	 * 
	 * @throws EIDASSAMLEngineException the EIDASSAML engine exception
	 */
	private void validateParamAuthnReq(final EIDASAuthnRequest request)
	throws EIDASSAMLEngineException {
		LOG.trace("Validate parameters from authentication request.");

		// URL to which Authentication Response must be sent.
		if (getExtensionProcessor().getFormat()==SAMLExtensionFormat.STORK10 && StringUtils.isBlank(request.getAssertionConsumerServiceURL())) {
			throw new EIDASSAMLEngineException(EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"SamlEngine: Assertion Consumer Service URL is mandatory.");
		}

		// the name of the original service provider requesting the
		// authentication.
		if (StringUtils.isBlank(request.getProviderName())) {
			throw new EIDASSAMLEngineException(EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"SamlEngine: Service Provider is mandatory.");
		}

		// object that contain all attributes requesting.
		if (request.getPersonalAttributeList() == null
				|| request.getPersonalAttributeList().isEmpty()) {
			throw new EIDASSAMLEngineException(EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"attributeQueries is null or empty.");
		}

		// Quality authentication assurance level.
        int qaa=request.getQaa();
		if (getExtensionProcessor().getFormat()==SAMLExtensionFormat.STORK10 && ( qaa< QAAAttribute.MIN_VALUE)
				|| (qaa > QAAAttribute.MAX_VALUE)) {
			throw new EIDASSAMLEngineException(EIDASErrors.QAALEVEL.errorCode(),
                    EIDASErrors.QAALEVEL.errorCode(),"Qaal: " + request.getQaa()+ ", is invalid.");
		}

	}


	/**
	 * Validate parameters from response.
	 * 
	 * @param request the request
	 * @param responseAuthReq the response authentication request
	 * 
	 * @throws EIDASSAMLEngineException the EIDASSAML engine exception
	 */
	private void validateParamResponse(final EIDASAuthnRequest request,
			final EIDASAuthnResponse responseAuthReq)
	throws EIDASSAMLEngineException {
		LOG.trace("Validate parameters response.");
		if (StringUtils.isBlank(request.getIssuer())) {
			throw new EIDASSAMLEngineException(EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"Issuer must be not empty or null.");
		}

		if (responseAuthReq.getPersonalAttributeList() == null
				|| responseAuthReq.getPersonalAttributeList().isEmpty()) {
			LOG.error(SAML_EXCHANGE, "PersonalAttributeList is null or empty.");
			throw new EIDASSAMLEngineException(EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"PersonalAttributeList is null or empty.");
		}

		if (StringUtils.isBlank(request.getAssertionConsumerServiceURL())) {
			throw new EIDASSAMLEngineException(EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"assertionConsumerServiceURL is null or empty.");
		}

		if (StringUtils.isBlank(request.getSamlId())) {
			throw new EIDASSAMLEngineException(EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"request ID is null or empty.");
		}
		initResponseProcessor(request);
	}
	private void initResponseProcessor(final EIDASAuthnRequest request){
		if(extensionProcessor==null && !StringUtils.isEmpty(request.getMessageFormatName())){
			for(ExtensionProcessorI extensionProcessorI:getExtensionProcessors()){
				if(request.getMessageFormatName().equalsIgnoreCase(extensionProcessorI.getFormat().getName())){
					setExtensionProcessor(extensionProcessorI);
					break;
				}
			}
		}
		if(LOG.isDebugEnabled()) {
			LOG.debug("initResponseProcessor: Message format is " + (extensionProcessor == null ? null : extensionProcessor.getFormat().getName()));
		}
	}

	/**
	 * Validate parameter from response fail.
	 * 
	 * @param request the request
	 * @param response the response
	 * 
	 * @throws EIDASSAMLEngineException the EIDASSAML engine exception
	 */
	private void validateParamResponseFail(final EIDASAuthnRequest request,
			final EIDASAuthnResponse response) throws EIDASSAMLEngineException {
		LOG.trace("Validate parameters response fail.");
		if (StringUtils.isBlank(response.getStatusCode())) {
			throw new EIDASSAMLEngineException(EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"Code error it's null or empty.");
		}

		if (StringUtils.isBlank(request.getAssertionConsumerServiceURL())) {
			throw new EIDASSAMLEngineException(EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"assertionConsumerServiceURL is null or empty.");
		}

		if (StringUtils.isBlank(request.getSamlId())) {
			throw new EIDASSAMLEngineException(EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"request ID is null or empty.");
		}
		initResponseProcessor(request);
	}

	/**
	 * Validate authentication request.
	 * 
	 * @param tokenSaml the token SAML
	 * 
	 * @return the authentication request
	 * 
	 * @throws EIDASSAMLEngineException the EIDASSAML engine exception
	 */
	public EIDASAuthnRequest validateEIDASAuthnRequest(final byte[] tokenSaml)
	throws EIDASSAMLEngineException {
		LOG.trace("validateEIDASAuthnRequest");

        if (tokenSaml == null) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : Saml authentication request is null.");
            throw new EIDASSAMLEngineException(EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"Saml authentication request is null.");
        }
        validateSchema(new String(tokenSaml, Charset.forName("UTF-8")));

		final AuthnRequest samlRequest = validateRequestHelper(tokenSaml);
		LOG.trace("Generate EIDASAuthnRequest.");
		final EIDASAuthnRequest authnRequest = getExtensionProcessor().processExtensions(samlRequest.getExtensions());

        if (samlRequest.getSignature() != null) {
            authnRequest.setCountry(this.getCountry(samlRequest.getSignature().getKeyInfo()));
            authnRequest.setAlias(this.getAlias(samlRequest.getSignature().getKeyInfo(), super.getSigner().getTrustStore()));
        }
		extractLoA(samlRequest, authnRequest);
        authnRequest.setSamlId(samlRequest.getID());
        authnRequest.setDestination(samlRequest.getDestination());
        authnRequest.setAssertionConsumerServiceURL(samlRequest.getAssertionConsumerServiceURL());

		authnRequest.setProviderName(samlRequest.getProviderName());
		authnRequest.setIssuer(samlRequest.getIssuer().getValue());
        authnRequest.setBinding(SAMLEngineUtils.getBindingMethod(samlRequest.getProtocolBinding()));
		authnRequest.setEidasNameidFormat(samlRequest.getNameIDPolicy()==null?null:samlRequest.getNameIDPolicy().getFormat());
        authnRequest.setMessageFormatName(getExtensionProcessor().getFormat().getName());

		//Delete unknown elements from requested ones
		final Iterator<PersonalAttribute> iterator = authnRequest.getPersonalAttributeList().iterator();
        IPersonalAttributeList cleanPerAttrList = (PersonalAttributeList) authnRequest.getPersonalAttributeList();
		while (iterator.hasNext()) {

			final PersonalAttribute attribute = iterator.next();

			// Verify if the attribute name exists.
			final String attributeName = extensionProcessor.getAttributeFullName(this, attribute.getName());

			if (StringUtils.isBlank(attributeName)) {
				LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : Attribute name: {} was not found. It will be removed from the request object", attribute.getName());
				cleanPerAttrList.remove(attribute.getName());
			}

		}	
		authnRequest.setPersonalAttributeList(cleanPerAttrList);

		return authnRequest;

	}

	private void extractLoA(AuthnRequest samlRequest, EIDASAuthnRequest authnRequest) throws EIDASSAMLEngineException{
		if(samlRequest.getRequestedAuthnContext()!=null && !samlRequest.getRequestedAuthnContext().getAuthnContextClassRefs().isEmpty()){
			RequestedAuthnContext rac = samlRequest.getRequestedAuthnContext();
            if(null==rac.getComparison()){
                throw new EIDASSAMLEngineException(EIDASErrors.INVALID_LOA_VALUE.errorCode(),
                        EIDASErrors.INVALID_LOA_VALUE.errorMessage());
            }
			String comparison = rac.getComparison().toString();
			List<AuthnContextClassRef> authnContexts=rac.getAuthnContextClassRefs();
			for(AuthnContextClassRef contextRef:authnContexts) {
				EidasLoaLevels level = EidasLoaLevels.getLevel(contextRef.getAuthnContextClassRef());
				if (level != null && EidasLoaCompareType.getCompareType(comparison)!=null) {
					authnRequest.setEidasLoA(level.stringValue());
					authnRequest.setEidasLoACompareType(EidasLoaCompareType.getCompareType(comparison).stringValue());
					break;
				}else if(!StringUtils.isEmpty(contextRef.getAuthnContextClassRef())){
					throw new EIDASSAMLEngineException(EIDASErrors.INVALID_LOA_VALUE.errorCode(),
							EIDASErrors.INVALID_LOA_VALUE.errorMessage());
				}
			}
		}
	}
    private AuthnRequest validateRequestHelper(final byte[] tokenSaml) throws EIDASSAMLEngineException{
        LOG.trace("Validate AuthnRequest");
		AuthnRequest samlRequest=null;
        ExtensionProcessorI currentProcessor=null;
		Exception []validationErrors=new Exception[getExtensionProcessors().length];
        try {
            if(extensionProcessor!=null) {
				try {
					samlRequest = validateRequestHelper(extensionProcessor, tokenSaml);
				}catch(ValidationException e){
					throw new EIDASSAMLEngineException(EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(), EIDASErrors.MESSAGE_VALIDATION_ERROR.errorMessage(), e);
				}
            }

			for (int i = 0; samlRequest == null && i < getExtensionProcessors().length; i++) {
				try {
					ExtensionProcessorI trialExtensionProcessor = getExtensionProcessors()[i];
					samlRequest = validateRequestHelper(trialExtensionProcessor, tokenSaml);
				}catch(ValidationException e){
					validationErrors[i]=e;
				}catch(EIDASSAMLEngineException e){
					if(EIDASErrors.SAML_ENGINE_NO_METADATA.errorCode().equalsIgnoreCase(e.getErrorCode())){
						LOG.error("{} cannot retrieve metadata for validating request ", e.getErrorCode());
						continue;
					}else{
						validationErrors[i]=e;
					}
				}
			}
        }catch(EIDASSAMLEngineException e){
			throw e;
		}catch (Exception e) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : ValidationException: validate AuthRequest.", e.getMessage());
            LOG.debug("ValidationException: validate AuthRequest.", e);
            throw new EIDASSAMLEngineException(EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    EIDASErrors.MESSAGE_VALIDATION_ERROR.errorMessage(),e);
        }
        if(samlRequest==null){
			setExtensionProcessor(currentProcessor);
			ValidationException validationError=buildValidationError(validationErrors);
			if(validationError!=null){
				throw new EIDASSAMLEngineException(EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
						EIDASErrors.MESSAGE_VALIDATION_ERROR.errorMessage(), validationError);
			}else {
				throw new EIDASSAMLEngineException(EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
						EIDASErrors.MESSAGE_VALIDATION_ERROR.errorMessage());
			}
        }
		return samlRequest;
    }

	private ValidationException buildValidationError(Exception[] validationErrors){
		StringBuffer validationErrorMessage=new StringBuffer();
		//some of the validation messages may appear several times (for each processor)
		Set<String> validationMessages=new HashSet<String>();
		for(int i=0;i<validationErrors.length;i++){
			if(validationErrors[i]!=null){
				validationMessages.add(validationErrors[i].getMessage());
			}
		}
		for(String message:validationMessages){
			validationErrorMessage.append(message).append(VALIDATION_MESSAGE_SEPARATOR);
		}
		if(validationErrorMessage.length()>0){
			return new ValidationException(validationErrorMessage.toString());
		}else{
			return null;
		}
	}

	private AuthnRequest validateRequestHelper(ExtensionProcessorI extensionProcessor, final byte[] tokenSaml) throws EIDASSAMLEngineException, ValidationException{
		AuthnRequest samlRequest=null;
		ValidatorSuite suite = Configuration.getValidatorSuite(extensionProcessor.getRequestValidatorId());
		extensionProcessor.configureExtension();
		samlRequest = (AuthnRequest) validateEidasSaml(tokenSaml, extensionProcessor.getFormat().getName());
		try {
			suite.validate(samlRequest);
			if(tryProcessExtensions(extensionProcessor, samlRequest)) {
                setExtensionProcessor(extensionProcessor);
				LOG.debug("validation with "+extensionProcessor.getClass().getName()+" succeeded !!!");
                return samlRequest;
            }else{
                samlRequest=null;
            }
		}catch (ValidationException e) {
			LOG.debug("validation with " + extensionProcessor.getClass().getName() + " not succeeded:", e);
			throw e;
		}
		return samlRequest;
	}


    private Response computeAuxResponse(final byte[] tokenSaml)throws EIDASSAMLEngineException{
        Response samlResponseAux = null;
        try {
            samlResponseAux = (Response) validateEidasSaml(tokenSaml, extensionProcessor==null?null:extensionProcessor.getFormat().getName());
            if(decryptResponse()) {
                /*
                    In the @eu.eidas.encryption.SAMLAuthnResponseDecrypter.decryptSAMLResponse method when inserting
                    the decrypted Assertions the DOM resets to null. Marsahlling it again resolves it.
                    More info in the links belows
                    https://jira.spring.io/browse/SES-148
                    http://digitaliser.dk/forum/2621692
                */
                super.noSignAndMarshall(samlResponseAux);
            }
        } catch (SAMLEngineException e) {
            LOG.warn("error validating the response ", e.getMessage());
            LOG.debug("error validating the response", e);
        }
        return samlResponseAux;
    }

    private void validateSamlResponse(final Response samlResponse)throws EIDASSAMLEngineException{
        LOG.trace("Validate AuthnResponse");
        ValidatorSuite suite = Configuration.getValidatorSuite(getExtensionProcessor().getResponseValidatorId());
        try {
            suite.validate(samlResponse);
        } catch (ValidationException e) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : ValidationException: validate AuthResponse.", e.getMessage());
            LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : ValidationException: validate AuthResponse.", e);
            throw new EIDASSAMLEngineException(EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    EIDASErrors.MESSAGE_VALIDATION_ERROR.errorMessage(),e);
        } catch (Exception e) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : ValidationException: validate AuthResponse.", e.getMessage());
            LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : ValidationException: validate AuthResponse.", e);
            throw new EIDASSAMLEngineException(EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    EIDASErrors.MESSAGE_VALIDATION_ERROR.errorMessage(),e);
        }

    }
    private EIDASAuthnResponse createEidasResponse(final Response samlResponse){
        LOG.trace("Create EidasAuthResponse.");
        final EIDASAuthnResponse authnResponse = new EIDASAuthnResponse();

        authnResponse.setCountry(this.getCountry(samlResponse.getSignature()
                .getKeyInfo()));

        LOG.trace("Set ID.");
        authnResponse.setSamlId(samlResponse.getID());
        LOG.trace("Set InResponseTo.");
        authnResponse.setInResponseTo(samlResponse.getInResponseTo());
        LOG.trace("Set statusCode.");
        authnResponse.setStatusCode(samlResponse.getStatus().getStatusCode()
                .getValue());

        // Subordinate code.
        if (samlResponse.getStatus().getStatusCode().getStatusCode() != null) {
            authnResponse.setSubStatusCode(samlResponse.getStatus()
                    .getStatusCode().getStatusCode().getValue());
        }

        if (samlResponse.getStatus().getStatusMessage() != null) {
            LOG.trace("Set statusMessage.");
            authnResponse.setMessage(samlResponse.getStatus()
                    .getStatusMessage().getMessage());
        }
		authnResponse.setEncrypted(samlResponse.getEncryptedAssertions()!=null && !samlResponse.getEncryptedAssertions().isEmpty());
        return authnResponse;
    }
	/**
	 * Validate authentication response.
	 * 
	 * @param tokenSaml the token SAML
	 * @param userIP the user IP
	 * 
	 * @return the authentication response
	 * 
	 * @throws EIDASSAMLEngineException the EIDASSAML engine exception
	 */
    public EIDASAuthnResponse validateEIDASAuthnResponse(
			final byte[] tokenSaml, final String userIP, final long skewTimeInMillis)
	throws EIDASSAMLEngineException {
        LOG.trace("validateEIDASAuthnResponse");

        if (tokenSaml == null) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : Saml authentication response is null.");
            throw new EIDASSAMLEngineException(EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"Saml authentication response is null.");
        }

        validateSchema(new String(tokenSaml, Charset.forName("UTF-8")));

        final Response samlResponse = computeAuxResponse(tokenSaml);

        validateSamlResponse(samlResponse);

        final EIDASAuthnResponse authnResponse = createEidasResponse(samlResponse);
		LOG.trace("validateEidasResponse");
		final Assertion assertion = validateEidasResponse(samlResponse, userIP, skewTimeInMillis);
		
		if(assertion!=null){
			LOG.trace("Set notOnOrAfter.");
			authnResponse.setNotOnOrAfter(assertion.getConditions().getNotOnOrAfter());

			LOG.trace("Set notBefore.");
			authnResponse.setNotBefore(assertion.getConditions().getNotBefore());

			authnResponse.setAudienceRestriction((assertion
					.getConditions().getAudienceRestrictions().get(0))
					.getAudiences().get(0).getAudienceURI());
			if(!assertion.getAuthnStatements().isEmpty() && assertion.getAuthnStatements().get(0).getAuthnContext()!=null &&
					assertion.getAuthnStatements().get(0).getAuthnContext().getAuthnContextClassRef()!=null){
				authnResponse.setAssuranceLevel(assertion.getAuthnStatements().get(0).getAuthnContext().getAuthnContextClassRef().getAuthnContextClassRef());
			}
		}

		// Case no error.
		if (assertion!=null && StatusCode.SUCCESS_URI.equalsIgnoreCase(authnResponse
				.getStatusCode())) {
			LOG.trace("Status Success. Set PersonalAttributeList.");
			authnResponse.setPersonalAttributeList(generatePersonalAttributeList(assertion));
			authnResponse.setFail(false);
		} else {
			LOG.trace("Status Fail.");
			authnResponse.setFail(true);
		}
		LOG.trace("Return result.");
		return authnResponse;

	}
	/**
	 * Validate response.
	 * 
	 * @param samlResponse the SAML response
	 * @param userIP the user IP
	 * 
	 * @return the assertion
	 * 
	 * @throws EIDASSAMLEngineException the EIDASSAML engine exception
	 */
	private Assertion validateEidasResponse(final Response samlResponse, final String userIP, final Long skewTimeInMillis) throws EIDASSAMLEngineException {
		// Exist only one Assertion
		if (samlResponse.getAssertions() == null || samlResponse.getAssertions().isEmpty()) {
            //in replace of throwing  EIDASSAMLEngineException("Assertion is null or empty.")
			LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : Assertion is null, empty or the response is encrypted and the decryption is not active.");
			return null;
		}

		final Assertion assertion = (Assertion) samlResponse.getAssertions().get(0);

        verifyMethodBearer(userIP, assertion);

        // Applying skew time conditions before testing it
        DateTime skewedNotBefore = new DateTime(assertion.getConditions().getNotBefore().getMillis() - skewTimeInMillis, DateTimeZone.UTC);
        DateTime skewedNotOnOrAfter = new DateTime(assertion.getConditions().getNotOnOrAfter().getMillis() + skewTimeInMillis, DateTimeZone.UTC);
        LOG.debug(SAML_EXCHANGE, "skewTimeInMillis : {}", skewTimeInMillis);
        LOG.debug(SAML_EXCHANGE, "skewedNotBefore       : {}", skewedNotBefore);
        LOG.debug(SAML_EXCHANGE, "skewedNotOnOrAfter    : {}", skewedNotOnOrAfter);
        assertion.getConditions().setNotBefore(skewedNotBefore);
        assertion.getConditions().setNotOnOrAfter(skewedNotOnOrAfter);

        verifyConditions(assertion);

		return assertion;
	}

    private void verifyConditions(Assertion assertion) throws EIDASSAMLEngineException {
        Conditions conditions = assertion.getConditions();
        final DateTime serverDate = clock.getCurrentTime();
        LOG.debug("serverDate            : " + serverDate);

        if (conditions.getAudienceRestrictions() == null || conditions.getAudienceRestrictions().isEmpty()) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : AudienceRestriction must be present");
            throw new EIDASSAMLEngineException(EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"AudienceRestriction must be present");
        }
        if (conditions.getOneTimeUse() == null) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : OneTimeUse must be present");
            throw new EIDASSAMLEngineException(EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"OneTimeUse must be present");
        }
        if (conditions.getNotBefore() == null) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : NotBefore must be present");
            throw new EIDASSAMLEngineException(EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"NotBefore must be present");
        }
        if (conditions.getNotBefore().isAfter(serverDate)) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : Current time is before NotBefore condition");
            throw new EIDASSAMLEngineException(EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"Current time is before NotBefore condition");
        }
        if (conditions.getNotOnOrAfter() == null) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : NotOnOrAfter must be present");
            throw new EIDASSAMLEngineException(EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"NotOnOrAfter must be present");
        }
        if (conditions.getNotOnOrAfter().isBeforeNow()) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : Current time is after NotOnOrAfter condition");
            throw new EIDASSAMLEngineException(EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"Current time is after NotOnOrAfter condition");
        }
        if (assertion.getConditions().getNotOnOrAfter().isBefore(serverDate)) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : Token date expired (getNotOnOrAfter =  " + assertion.getConditions().getNotOnOrAfter() + ", server_date: " + serverDate + ")");
            throw new EIDASSAMLEngineException(EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"Token date expired (getNotOnOrAfter =  " + assertion.getConditions().getNotOnOrAfter() + " ), server_date: " + serverDate);
        }
    }

    private void verifyMethodBearer(String userIP, Assertion assertion) throws EIDASSAMLEngineException {
        LOG.trace("Verified method Bearer");
        for (final Iterator<SubjectConfirmation> iter = assertion.getSubject()
                .getSubjectConfirmations().iterator(); iter.hasNext();) {
            final SubjectConfirmation element = iter.next();
            final boolean isBearer = SubjectConfirmation.METHOD_BEARER
            .equals(element.getMethod());

            final boolean ipValidate = super.getSamlCoreProperties()
            .isIpValidation();

            if (ipValidate) {
                if (isBearer) {
                    if (StringUtils.isBlank(userIP)) {
                        LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : browser_ip is null or empty.");
                        throw new EIDASSAMLEngineException(EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                                EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"browser_ip is null or empty.");
                    } else if (StringUtils.isBlank(element.getSubjectConfirmationData().getAddress())) {
                        LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : token_ip attribute is null or empty.");
                        throw new EIDASSAMLEngineException(EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                                EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"token_ip attribute is null or empty.");
                    }
                }
                final boolean ipEqual = element.getSubjectConfirmationData().getAddress().equals(userIP);
                // Validation ipUser
                if (!ipEqual && ipValidate) {
                    LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : SubjectConfirmation BEARER: IPs doesn't match : token_ip [{}] browser_ip [{}]", element.getSubjectConfirmationData().getAddress(), userIP);
                    throw new EIDASSAMLEngineException(EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                            EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"IPs doesn't match : token_ip ("+ element.getSubjectConfirmationData().getAddress() + ") browser_ip ("+ userIP + ")");
                }
            }

        }
    }

    private void validateAssertionsSignature(Response samlObject) throws EIDASSAMLEngineException {
        try{
            for(Assertion a:samlObject.getAssertions()){
                if(a.isSigned()){
                    super.validateSignature(a, getExtensionProcessor().getFormat().getName());
                }
            }
        }catch(SAMLEngineException e){
            EIDASSAMLEngineException exc = new EIDASSAMLEngineException(EIDASErrors.INVALID_ASSERTION_SIGNATURE.errorCode(), EIDASErrors.INVALID_ASSERTION_SIGNATURE.errorMessage(), e);
            throw exc;
        }


    }

    private SignableSAMLObject validateEidasSamlSignature(SignableSAMLObject samlObject, String messageFormat)throws EIDASSAMLEngineException{
        boolean validateSign = true;
        LOG.debug(SAML_EXCHANGE, super.getSamlCoreProperties().getProperty("validateSignature"));
        if (StringUtils.isNotBlank(super.getSamlCoreProperties().getProperty("validateSignature"))) {
            validateSign = Boolean.valueOf(super.getSamlCoreProperties().getProperty("validateSignature"));
        }
        SignableSAMLObject validSamlObject=samlObject;
        if (validateSign) {
            LOG.trace("Validate Signature.");
            try {
				if ((samlObject instanceof Response || samlObject instanceof AuthnRequest) && validSamlObject.getSignature()==null){
						throw new SAMLEngineException(EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"Invalid signature");
				}
                if (samlObject instanceof Response){
                    setCountryResponseFrom(getCountry(samlObject.getSignature().getKeyInfo()));
                    LOG.debug(SAML_EXCHANGE, "Response received from country: " + getCountryResponseFrom());
                }
                validSamlObject = (SignableSAMLObject)super.validateSignature(samlObject, messageFormat);
                if (samlObject instanceof Response){
                    //check assertions signature, if any
                    validateAssertionsSignature((Response)samlObject);
                }
            } catch (SAMLEngineException e) {
                LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : SAMLEngineException validateSignature.", e.getMessage());
                LOG.debug(SAML_EXCHANGE, "SAMLEngineException validateSignature.", e);
                EIDASSAMLEngineException exc = new EIDASSAMLEngineException(e);
                if(EIDASErrors.isErrorCode(e.getMessage())){
                    exc.setErrorCode(e.getMessage());
                }
				if(EIDASErrors.isErrorCode(e.getErrorCode())){
					exc.setErrorCode(e.getErrorCode());
				}
                throw exc;
            }
        }
        return  validSamlObject;
    }
    /**
	 * Validate SAML.
	 * 
	 * @param tokenSaml the token SAML
	 * 
	 * @return the signable SAML object
	 * 
	 * @throws EIDASSAMLEngineException the EIDASSAML engine exception
	 */
	private SignableSAMLObject validateEidasSaml(final byte[] tokenSaml, String messageFormat) throws EIDASSAMLEngineException {

		LOG.trace("Validate saml message.");

		if (tokenSaml == null) {
			LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : Saml authentication request is null.");
			throw new EIDASSAMLEngineException(EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"Saml authentication request is null.");
		}

		LOG.trace("Generate AuthnRequest from request.");
		SignableSAMLObject samlObject;

		try {
			samlObject = (SignableSAMLObject) super.unmarshall(tokenSaml);
		} catch (SAMLEngineException e) {
			LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : SAMLEngineException unmarshall.", e.getMessage());
			LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : SAMLEngineException unmarshall.", e);
			throw new EIDASSAMLEngineException(EIDASErrors.INVALID_ENCRYPTION_ALGORITHM.errorCode(),
                    EIDASErrors.INVALID_ENCRYPTION_ALGORITHM.errorMessage(),e);
		}
        samlObject = validateEidasSamlSignature(samlObject, messageFormat);
        LOG.trace("Validate Schema.");
		final ValidatorSuite validatorSuite = Configuration.getValidatorSuite("saml2-core-schema-validator");
		try {
			validatorSuite.validate(samlObject);
		} catch (ValidationException e) {
			LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : ValidationException.", e.getMessage());
			LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : ValidationException.", e);
			throw new EIDASSAMLEngineException(EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    EIDASErrors.MESSAGE_VALIDATION_ERROR.errorMessage(),e);
		}

		return samlObject;
	}
    /**
     * @deprecated
     */
    @Deprecated
    public EIDASAuthnRequest generateEIDASAuthnRequestWithoutValidation(
            final EIDASAuthnRequest request) throws EIDASSAMLEngineException {
        LOG.trace("Generate SAMLAuthnRequest.");

        // Validate Parameters mandatories
		selectFormat(request.getMessageFormatName());

        final AuthnRequest authnRequestAux = SAMLEngineUtils
                .generateSAMLAuthnRequest(SAMLEngineUtils.generateNCName(),
                        SAMLVersion.VERSION_20, SAMLEngineUtils
                        .getCurrentTime());

        // Set name spaces.
        setRequestNameSpaces(authnRequestAux);

        // Add parameter Mandatory 
        authnRequestAux.setForceAuthn(Boolean.TRUE);

        // Add parameter Mandatory 
        authnRequestAux.setIsPassive(Boolean.FALSE);

        authnRequestAux.setAssertionConsumerServiceURL(request
                .getAssertionConsumerServiceURL());

        authnRequestAux.setProviderName(request.getProviderName());

        // Add protocol binding
		if(SAMLEngineUtils.isEidasFormat(request)){
			authnRequestAux.setProtocolBinding(null);
		}else {
			authnRequestAux.setProtocolBinding(request.getBinding() == null ? null : getProtocolBinding(request.getBinding()));
		}

        // Add parameter optional 
        // Destination is mandatory
        // The application must to know the destination
        if (StringUtils.isNotBlank(request.getDestination())) {
            authnRequestAux.setDestination(request.getDestination());
        }

        // Consent is optional. Set from SAMLEngine.xml - consent.
        authnRequestAux.setConsent(super.getSamlCoreProperties()
                .getConsentAuthnRequest());

        final Issuer issuer = SAMLEngineUtils.generateIssuer();

        if (request.getIssuer() != null) {
            issuer.setValue(SAMLEngineUtils.getValidIssuerValue(request.getIssuer()));
        } else {
            issuer.setValue(super.getSamlCoreProperties().getRequester());
        }

        // Optional 
        final String formatEntity = super.getSamlCoreProperties()
                .getFormatEntity();
        if (StringUtils.isNotBlank(formatEntity)) {
            issuer.setFormat(formatEntity);
        }

        authnRequestAux.setIssuer(issuer);
		addAuthnContext(request, authnRequestAux);

        // Generate format extensions.
        final Extensions formatExtensions = getExtensionProcessor().generateExtensions(this, request);
        // add the extensions to the SAMLAuthnRequest
        authnRequestAux.setExtensions(formatExtensions);
		addNameIDPolicy(authnRequestAux, request.getEidasNameidFormat());

        // the result contains an authentication request token (byte[]),
        // identifier of the token, and all parameters from the request.
        final EIDASAuthnRequest authRequest = getExtensionProcessor().processExtensions(authnRequestAux
				.getExtensions());

        try {
            authRequest.setTokenSaml(super.signAndMarshall(authnRequestAux, getExtensionProcessor().getFormat().getName()));
        } catch (SAMLEngineException e) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : Sign and Marshall.", e.getMessage());
            LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : Sign and Marshall.", e);
            throw new EIDASSAMLEngineException(
					EIDASUtil.getConfig(EIDASErrors.INTERNAL_ERROR.errorCode()),
					EIDASUtil.getConfig(EIDASErrors.INTERNAL_ERROR.errorMessage()), e);
        }

        authRequest.setSamlId(authnRequestAux.getID());
        authRequest.setDestination(authnRequestAux.getDestination());
        authRequest.setAssertionConsumerServiceURL(authnRequestAux
                .getAssertionConsumerServiceURL());

        authRequest.setProviderName(authnRequestAux.getProviderName());
        authRequest.setIssuer(authnRequestAux.getIssuer().getValue());

        return authRequest;
    }

    public EIDASAuthnRequest generateEIDASAuthnRequestWithoutSign(
            final EIDASAuthnRequest request) throws EIDASSAMLEngineException {
        LOG.trace("Generate SAMLAuthnRequest.");

        // Validate Parameters mandatories

        final AuthnRequest authnRequestAux = SAMLEngineUtils
                .generateSAMLAuthnRequest(SAMLEngineUtils.generateNCName(),
                        SAMLVersion.VERSION_20, SAMLEngineUtils
                        .getCurrentTime());

        // Set name spaces.
        setRequestNameSpaces(authnRequestAux);

        // Add parameter Mandatory 
        authnRequestAux.setForceAuthn(Boolean.TRUE);

        // Add parameter Mandatory 
        authnRequestAux.setIsPassive(Boolean.FALSE);

        authnRequestAux.setAssertionConsumerServiceURL(request
                .getAssertionConsumerServiceURL());

        authnRequestAux.setProviderName(request.getProviderName());

        // Add protocol binding
		if(SAMLEngineUtils.isEidasFormat(request)){
			authnRequestAux.setProtocolBinding(null);
		}else {
			authnRequestAux.setProtocolBinding(request.getBinding() == null ? null : getProtocolBinding(request.getBinding()));
		}

        // Add parameter optional 
        // Destination is mandatory 
        // The application must to know the destination
        if (StringUtils.isNotBlank(request.getDestination())) {
            authnRequestAux.setDestination(request.getDestination());
        }

        // Consent is optional. Set from SAMLEngine.xml - consent.
        authnRequestAux.setConsent(super.getSamlCoreProperties()
                .getConsentAuthnRequest());

        final Issuer issuer = SAMLEngineUtils.generateIssuer();

        if (request.getIssuer() != null) {
            issuer.setValue(SAMLEngineUtils.getValidIssuerValue(request.getIssuer()));
        } else {
            issuer.setValue(super.getSamlCoreProperties().getRequester());
        }

        // Optional 
        final String formatEntity = super.getSamlCoreProperties()
                .getFormatEntity();
        if (StringUtils.isNotBlank(formatEntity)) {
            issuer.setFormat(formatEntity);
        }

        authnRequestAux.setIssuer(issuer);
		addAuthnContext(request, authnRequestAux);

        // Generate format extensions.
        final Extensions formatExtensions = getExtensionProcessor().generateExtensions(this, request);
        // add the extensions to the SAMLAuthnRequest
        authnRequestAux.setExtensions(formatExtensions);
		addNameIDPolicy(authnRequestAux, request.getEidasNameidFormat());

        // the result contains an authentication request token (byte[]),
        // identifier of the token, and all parameters from the request.
        final EIDASAuthnRequest authRequest = getExtensionProcessor().processExtensions(authnRequestAux
				.getExtensions());

        try {
            authRequest.setTokenSaml(super.noSignAndMarshall(authnRequestAux));
        } catch (SAMLEngineException e) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : Sign and Marshall.", e.getMessage());
            LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : Sign and Marshall.", e);
            throw new EIDASSAMLEngineException(
					EIDASErrors.INTERNAL_ERROR.errorCode(),
					EIDASErrors.INTERNAL_ERROR.errorMessage(), e);
        }

        authRequest.setSamlId(authnRequestAux.getID());
        authRequest.setDestination(authnRequestAux.getDestination());
        authRequest.setAssertionConsumerServiceURL(authnRequestAux
                .getAssertionConsumerServiceURL());

        authRequest.setProviderName(authnRequestAux.getProviderName());
        authRequest.setIssuer(authnRequestAux.getIssuer().getValue());

        return authRequest;
    }
    public static String validateSchema(String samlRequestXML) throws EIDASSAMLEngineException {
        Document document;
        javax.xml.validation.Schema schema = null;
        javax.xml.validation.Validator validator;

        try {
            BasicParserPool ppMgr = getNewBasicSecuredParserPool();
            ppMgr.setNamespaceAware(true);
            InputStream inputStream = new ByteArrayInputStream(samlRequestXML.getBytes("UTF-8"));
            document = ppMgr.parse(inputStream);
            Element samlElemnt = document.getDocumentElement();

            schema = SAMLSchemaBuilder.getSAML11Schema();

            validator = schema.newValidator();
            DOMSource domSrc = new DOMSource(samlElemnt);
            validator.validate(domSrc);
        } catch (XMLParserException e) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : Validate schema exception", e.getMessage());
            LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : Validate schema exception", e);
            if (e.getCause().toString().contains("DOCTYPE is disallowed")){
                throw new EIDASSAMLEngineException(EIDASUtil.getConfig(EIDASErrors.DOC_TYPE_NOT_ALLOWED.errorCode()),
						EIDASErrors.DOC_TYPE_NOT_ALLOWED.errorCode(), "SAML request contains a DOCTYPE which is not allowed for security reason");
            } else {
                throw new EIDASSAMLEngineException(EIDASUtil.getConfig(EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode()),
						EIDASErrors.MESSAGE_VALIDATION_ERROR.errorMessage(), e);
            }
        } catch (SAXException e) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : Validate schema exception", e.getMessage());
            LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : Validate schema exception", e);
            throw new EIDASSAMLEngineException(EIDASUtil.getConfig(EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode()),
					EIDASErrors.MESSAGE_VALIDATION_ERROR.errorMessage(), e);
        } catch (IOException e) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : Validate schema exception", e.getMessage());
            LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : Validate schema exception", e);
            throw new EIDASSAMLEngineException(EIDASUtil.getConfig(EIDASErrors.MESSAGE_VALIDATION_ERROR.errorCode()),
					EIDASErrors.MESSAGE_VALIDATION_ERROR.errorMessage(), e);
        }
        return samlRequestXML;
    }

    /**
	 * Resign authentication request ( for validation purpose).
	 * @return the resigned request
	 * @throws EIDASSAMLEngineException the EIDASSAML engine exception
	 */
	public EIDASAuthnRequest resignEIDASAuthnRequest(final EIDASAuthnRequest request, boolean changeProtocol) throws EIDASSAMLEngineException {
        LOG.trace("Generate SAMLAuthnRequest.");

        EIDASAuthnRequest authRequest = null;
        AuthnRequest authnRequestAux = null;

        try {
            authRequest = (EIDASAuthnRequest) request.clone();
        } catch (CloneNotSupportedException e) {
            LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : Clone not supported in resignEIDASAuthnRequest {}", e);
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : Clone not supported in resignEIDASAuthnRequest {}", e.getMessage());
        }

        byte[] tokenSaml  = request.getTokenSaml() ;

        try {
            authnRequestAux = (AuthnRequest) unmarshall(tokenSaml);
			if(SAMLEngineUtils.isEidasFormat(request)){
				authnRequestAux.setProtocolBinding(null);
			}else if(authnRequestAux.getProtocolBinding()==null || changeProtocol) {
				authnRequestAux.setProtocolBinding(getProtocolBinding(authRequest.getBinding()));
			}
        } catch (SAMLEngineException e) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : resignEIDASAuthnRequest {}", e.getMessage());
            LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : resignEIDASAuthnRequest {}", e);
        }

        try {
            authRequest.setTokenSaml(super.signAndMarshall(authnRequestAux, getExtensionProcessor().getFormat().getName()));
        } catch (SAMLEngineException e) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : resignEIDASAuthnRequest : Sign and Marshall.{}", e.getMessage());
            LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : resignEIDASAuthnRequest : Sign and Marshall.{}", e);
            throw new EIDASSAMLEngineException(EIDASErrors.INTERNAL_ERROR.errorCode(),
                    EIDASErrors.INTERNAL_ERROR.errorMessage(),e);
        }
        return authRequest;
    }
    public EIDASAuthnRequest resignEIDASAuthnRequest(final EIDASAuthnRequest request) throws EIDASSAMLEngineException {
        return resignEIDASAuthnRequest(request,false);
    }
     /**
     * Resign tokenSaml ( for validation purpose).
     * @return the resigned request
     * @throws EIDASSAMLEngineException the EIDASSAML engine exception
     */
    public byte[] resignEIDASTokenSAML(final byte[] tokenSaml) throws EIDASSAMLEngineException {
        LOG.trace("Generate SAMLAuthnRequest.");

        AuthnRequest authnRequestAux = null;

        try {
            authnRequestAux = (AuthnRequest) unmarshall(tokenSaml);
            releaseExtensionsDom(authnRequestAux);
		} catch (SAMLEngineException e) {
            LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : unmarshall {}", e);
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : unmarshall {}", e.getMessage());
        }
        if(authnRequestAux==null){
            throw new EIDASSAMLEngineException(EIDASErrors.INTERNAL_ERROR.errorCode(),
                    EIDASErrors.INTERNAL_ERROR.errorCode(), "invalid AuthnRequest");
        }

        try {
            return super.signAndMarshall(authnRequestAux, getExtensionProcessor().getFormat().getName());
        } catch (SAMLEngineException e) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : resignEIDASTokenSAML : Sign and Marshall.", e);
            LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : resignEIDASTokenSAML : Sign and Marshall.", e.getMessage());
            throw new EIDASSAMLEngineException(EIDASErrors.INTERNAL_ERROR.errorCode(),
                    EIDASErrors.INTERNAL_ERROR.errorMessage(),e);
        }
    }

    private void releaseExtensionsDom(AuthnRequest authnRequestAux){
        if(authnRequestAux.getExtensions()==null){
            return;
        }
        authnRequestAux.getExtensions().releaseDOM();
        authnRequestAux.getExtensions().releaseChildrenDOM(true);
    }

    /**
     * Resigns the saml token checking previously if it is encrypted
     * @param tokenSaml
     * @return
     * @throws EIDASSAMLEngineException
     */
    public byte[] checkAndResignEIDASTokenSAML(final byte[] tokenSaml) throws EIDASSAMLEngineException {

        SignableSAMLObject samlObject = null;

        try {
            samlObject = (SignableSAMLObject) unmarshall(tokenSaml);
            samlObject = validateEidasSamlSignature(samlObject, getExtensionProcessor().getFormat().getName());
        } catch (SAMLEngineException e) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : unmarshall {}", e.getMessage());
            LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : unmarshall {}", e);
        }
        if(samlObject==null){
            throw new EIDASSAMLEngineException(EIDASErrors.INTERNAL_ERROR.errorCode(),
                    EIDASErrors.INTERNAL_ERROR.errorMessage(),"BUSINESS EXCEPTION : invalid AuthnRequest");
        }

        try {
            return super.signAndMarshall(samlObject, getExtensionProcessor().getFormat().getName());
        } catch (SAMLEngineException e) {
            LOG.debug(SAML_EXCHANGE,"BUSINESS EXCEPTION : checkAndResignEIDASTokenSAML : Sign and Marshall.", e);
            LOG.info(SAML_EXCHANGE,"BUSINESS EXCEPTION : checkAndResignEIDASTokenSAML : Sign and Marshall.", e.getMessage());
            throw new EIDASSAMLEngineException(
					EIDASErrors.INTERNAL_ERROR.errorCode(),
					EIDASErrors.INTERNAL_ERROR.errorMessage(), e);
        }
	}

	/**
	 * Returns true when the input contains an encrypted SAML Response
	 * @param tokenSaml
	 * @return
	 * @throws EIDASSAMLEngineException
	 */
	public boolean isEncryptedSamlResponse(final byte[] tokenSaml) throws EIDASSAMLEngineException {
		SignableSAMLObject samlObject = null;

		try {
			samlObject = (SignableSAMLObject) unmarshall(tokenSaml);
		} catch (SAMLEngineException e) {
			LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : unmarshall {}", e.getMessage());
			LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : unmarshall {}", e);
		}
		if( samlObject instanceof Response ){
			Response response=(Response)samlObject;
			return response.getEncryptedAssertions()!=null && !response.getEncryptedAssertions().isEmpty();
		}
		return false;

	}

    /**
     * computes SAML binding from http binding
     * @param binding
     * @return
     */
    private String getProtocolBinding(String binding){
        if(EIDASAuthnRequest.BINDING_REDIRECT.equalsIgnoreCase(binding)) {
            return SAMLConstants.SAML2_REDIRECT_BINDING_URI;
        }else if(EIDASAuthnRequest.BINDING_POST.equalsIgnoreCase(binding)){
            return SAMLConstants.SAML2_POST_BINDING_URI;
        }else if(EIDASAuthnRequest.BINDING_EMPTY.equalsIgnoreCase(binding)){
			return null;
		}
        return super.getSamlCoreProperties().getProtocolBinding();
    }
	ExtensionProcessorI extensionProcessor;
	public ExtensionProcessorI getExtensionProcessor(){
		if(extensionProcessor==null){
			setExtensionProcessor(new EidasExtensionProcessor());
		}
		return extensionProcessor;
	}
	public void setExtensionProcessor(ExtensionProcessorI extensionProcessor){
		this.extensionProcessor=extensionProcessor;
        if(extensionProcessor!=null) {
            this.extensionProcessor.configureExtension();
        }
	}

	ExtensionProcessorI availableExtensionProcessors[]=new ExtensionProcessorI[]{new EidasExtensionProcessor(),new StorkExtensionProcessor()};
	public ExtensionProcessorI[] getExtensionProcessors(){
//		ExtensionProcessorI returnedExtensionProcessors[]=new ExtensionProcessorI[2];
//		System.arraycopy(availableExtensionProcessors, 0, returnedExtensionProcessors, 0,availableExtensionProcessors.length);
		List<ExtensionProcessorI> processors=new ArrayList<ExtensionProcessorI>();
		Set<String> formatNames = super.getSamlCoreProperties().getSupportedMessageFormatNames();
		for(ExtensionProcessorI processor:availableExtensionProcessors){
			if(formatNames.contains(processor.getFormat().getName())){
				processors.add(processor);
			}
		}
		return processors.toArray(new ExtensionProcessorI[]{});
	}

    /**
     * init supported format from the requested attributes
     * Implementation note: currently, the set of supported attributes names for each format should be disjunct
     * @param attlist
     */
    public void initRequestedAttributes(Iterable<PersonalAttribute> attlist){
        Set<String> []supportedAttrSets=new Set[]{new HashSet<String>(EIDASAttributes.ATTRIBUTES_TO_SHORTNAMES.values()), new HashSet<String>(STORKAttributes.ATTRIBUTES_SET_NAMES.values())};
        ExtensionProcessorI[] extensionProcessors={new EidasExtensionProcessor(), new StorkExtensionProcessor()};
        for(PersonalAttribute att:attlist) {
            for (int i = 0; i < supportedAttrSets.length; i++) {
                Set<String> set = supportedAttrSets[i];
                if (set.contains(att.getName())) {
                    setExtensionProcessor(extensionProcessors[i]);
                    return;
                }
            }
        }

    }
    private boolean tryProcessExtensions(ExtensionProcessorI extensionProcessor, AuthnRequest samlRequest) throws ValidationException{
        try{
            EIDASAuthnRequest request =extensionProcessor.processExtensions(samlRequest.getExtensions());
            //format discriminator goes here
            if(request!=null){
                return extensionProcessor.isValidRequest(samlRequest);
            }
        }catch(EIDASSAMLEngineException e){
            throw new ValidationException(e);
        }
        return false;
    }

}
