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

package eu.stork.peps.auth.engine;

import eu.stork.peps.auth.commons.*;
import eu.stork.peps.auth.engine.core.*;
import eu.stork.peps.auth.engine.core.eidas.EidasExtensionProcessor;
import eu.stork.peps.auth.engine.core.eidas.GenericEidasAttributeType;
import eu.stork.peps.auth.engine.core.stork.QAAAttribute;
import eu.stork.peps.auth.engine.core.stork.StorkExtensionProcessor;
import eu.stork.peps.auth.engine.core.validator.STORKAttributes;
import eu.stork.peps.auth.engine.core.validator.eidas.EIDASAttributes;
import eu.stork.peps.configuration.SAMLBootstrap;
import eu.stork.peps.exceptions.SAMLEngineException;
import eu.stork.peps.exceptions.STORKSAMLEngineException;
import eu.stork.samlengineconfig.CertificateConfigurationManager;
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
import org.opensaml.xml.validation.Validator;
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
 * validation of SAML STORK requests and SAML STORK responses. Complaint with
 * "OASIS Secure Assertion Markup Language (SAML) 2.0, May 2005", but taking
 * into account STORK specific requirements.
 * 
 * @author fjquevedo
 * @author iinigo
 */
public final class STORKSAMLEngine extends AbstractSAMLEngine {

	/** The Constant LOG. */
	private static final Logger LOG = LoggerFactory.getLogger(STORKSAMLEngine.class.getName());
    private static final int HEXA=16;
    private static final String EIDAS_NATURALPERSON_IDENTIFIER="http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier";
    private static final String EIDAS_LEGALPERSON_IDENTIFIER="http://eidas.europa.eu/attributes/legalperson/LegalPersonIdentifier";

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
     * Creates an instance of STORKSAMLEngine.
     *
     * @param nameInstance the name instance
     * @return instance of STORKSAMLEngine
     */
    public static synchronized STORKSAMLEngine createSTORKSAMLEngine(final String nameInstance) throws STORKSAMLEngineException{
        return createSTORKSAMLEngine(nameInstance, null);
    }

	public static synchronized STORKSAMLEngine createSTORKSAMLEngine(final String nameInstance, CertificateConfigurationManager configManager) throws STORKSAMLEngineException{
		STORKSAMLEngine engine = null;
		LOG.info(SAML_EXCHANGE, "Get instance: {} ", nameInstance);
		try {
			engine = new STORKSAMLEngine(nameInstance.trim(), configManager);
		} catch (STORKSAMLEngineException e) {
			throw e;
		} catch (Exception e) {
			LOG.error("Error get instance: " + nameInstance+ " {}", e);
		}
		return engine;
	}

	private static AtomicLong counter = new AtomicLong(0);
    private long id;
	private STORKSAMLEngine(final String nameInstance, final CertificateConfigurationManager configManager) throws STORKSAMLEngineException, ConfigurationException  {
		this(nameInstance, DEFAULT_CONFIG_NAME, configManager);
	}
	/**
	 * Instantiate a new STORKSAML engine.
	 * 
	 * @param nameInstance the name instance
	 * 
	 * @throws STORKSAMLEngineException the STORKSAML engine exception
	 */
	private STORKSAMLEngine(final String nameInstance, final String configName, final CertificateConfigurationManager configManager) throws STORKSAMLEngineException, ConfigurationException  {
		// Initialization OpenSAML.
		super(nameInstance, configName, configManager);
        id=counter.incrementAndGet();
		LOG.trace("Register STORK objects provider.");
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
        if(obj instanceof STORKSAMLEngine){
            return id==((STORKSAMLEngine)obj).id;
        }
        return false;
    }
    public void setDigestMethodAlgorithm(String algorithm){
        BasicSecurityConfiguration config=SAMLEngineUtils.getStorkGlobalSecurityConfiguration();
        if(config!=null && StringUtils.isNotBlank(algorithm)) {
			config.setSignatureReferenceDigestMethod(SAMLEngineUtils.validateDigestAlgorithm(algorithm));
		}else {
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
	 * @throws STORKSAMLEngineException the STORKSAML engine exception
	 */
	private Response genAuthnRespBase(final Status status,
			final String assertConsumerURL, final String inResponseTo)
	throws STORKSAMLEngineException {
		LOG.debug("Generate Authentication Response base.");
		final Response response = SAMLEngineUtils.generateResponse(
				SAMLEngineUtils.generateNCName(),
				SAMLEngineUtils.getCurrentTime(), status);

		// Set name Spaces
		this.setResponseNameSpaces(response);

		// Mandatory STORK
		LOG.debug("Generate Issuer");
		final Issuer issuer = SAMLEngineUtils.generateIssuer();
		issuer.setValue(super.getSamlCoreProperties().getResponder());

		// Format Entity Optional STORK
		issuer.setFormat(super.getSamlCoreProperties().getFormatEntity());

		response.setIssuer(issuer);

		// destination Mandatory Stork
		if(assertConsumerURL!=null) {
			response.setDestination(assertConsumerURL.trim());
		}

		// inResponseTo Mandatory Stork
		response.setInResponseTo(inResponseTo.trim());

		// Optional STORK
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
	 * @throws STORKSAMLEngineException the STORKSAML engine exception
	 */
	private Assertion generateAssertion(final String ipAddress,
			final STORKAuthnRequest request, Response response, IPersonalAttributeList pal, final DateTime notOnOrAfter)
	throws STORKSAMLEngineException {
		LOG.trace("Generate Assertion.");

		// Mandatory STORK
		LOG.trace("Generate Issuer to Assertion");
		final Issuer issuerAssertion = SAMLEngineUtils.generateIssuer();
		issuerAssertion.setValue(response.getIssuer().getValue());

		// Format Entity Optional STORK
		issuerAssertion.setFormat(super.getSamlCoreProperties().getFormatEntity());

		final Assertion assertion = SAMLEngineUtils.generateAssertion(
				SAMLVersion.VERSION_20, SAMLEngineUtils.generateNCName(),
				SAMLEngineUtils.getCurrentTime(), issuerAssertion);

		final Subject subject = SAMLEngineUtils.generateSubject();

		// Mandatory STORK verified
		// String format = NameID.UNSPECIFIED
		// specification: 'SAML:2.0' exist
		// opensaml: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
		// opensaml  "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified"
		String format =request.getEidasNameidFormat();
		if(format==null) {
			format = SAMLExtensionFormat.EIDAS10 == getExtensionProcessor().getFormat() ? STORKAuthnRequest.NAMEID_FORMAT_PERSISTENT :STORKAuthnRequest.NAMEID_FORMAT_UNSPECIFIED;
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
					throw new STORKSAMLEngineException(PEPSErrors.INTERNAL_ERROR.errorCode(),
                            PEPSErrors.INTERNAL_ERROR.errorCode(),"ipAddress is null or empty");
				}
				element.getSubjectConfirmationData().setAddress(ipAddress.trim());
			}

			element.getSubjectConfirmationData().setRecipient(request.getAssertionConsumerServiceURL());
			element.getSubjectConfirmationData().setNotOnOrAfter(notOnOrAfter);
		}

		// The SAML 2.0 specification allows multiple SubjectConfirmations
		subject.getSubjectConfirmations().addAll(listSubjectConf);

		// Mandatory Stork
		assertion.setSubject(subject);

		// Conditions that MUST be evaluated when assessing the validity of
		// and/or when using the assertion.
		final Conditions conditions = this.generateConditions(SAMLEngineUtils.getCurrentTime(), notOnOrAfter, request.getIssuer());

		assertion.setConditions(conditions);

		LOG.trace("Generate stork Authentication Statement.");
		final AuthnStatement storkAuthnStat = this.generateStorkAuthStatement(ipAddress);
		assertion.getAuthnStatements().add(storkAuthnStat);

		return assertion;
	}

    private String getUniquenessIdentifier (final STORKAuthnRequest request, IPersonalAttributeList pal) throws STORKSAMLEngineException{
        for (PersonalAttribute attribute : pal) {

            String attributeName = getAttributeName(attribute);
            if(EIDAS_NATURALPERSON_IDENTIFIER.equals(attributeName) && !attribute.isEmptyValue()){
                return attribute.getValue().get(0);
            }
            if(EIDAS_LEGALPERSON_IDENTIFIER.equals(attributeName) && !attribute.isEmptyValue()){
                return attribute.getValue().get(0);
            }
        }
        return request.getCountry()+"/uniqueid";
    }

    private String getAttributeName(final PersonalAttribute attribute) throws STORKSAMLEngineException {
        if (StringUtils.isBlank(attribute.getName())) {
            LOG.info("BUSINESS EXCEPTION : ", SAML_EXCHANGE, ATTRIBUTE_EMPTY_LITERAL);
            throw new STORKSAMLEngineException(ATTRIBUTE_EMPTY_LITERAL);
        }

        final String attributeName = getAttributeName(attribute.getName());

        if (StringUtils.isBlank(attributeName)) {
            LOG.info("BUSINESS EXCEPTION : Attribute name: {} it is not known.", attribute.getName());
            throw new STORKSAMLEngineException(PEPSErrors.INTERNAL_ERROR.errorCode(),
                    PEPSErrors.INTERNAL_ERROR.errorCode(),"Attribute name: " + attribute.getName() + " it is not known.");
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
	 * @throws STORKSAMLEngineException the STORKSAML engine exception
	 * @throws IOException
	 */
	private AttributeStatement generateAttributeStatement(
			final IPersonalAttributeList personalAttrList,
			final boolean isHashing) throws STORKSAMLEngineException {
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
									boolean simpleEmpty, boolean complexEmpty,final boolean isHashing)throws STORKSAMLEngineException {
		String attributeName = getAttributeName(attribute);
		if (!simpleEmpty && !complexEmpty) {
			throw new STORKSAMLEngineException(PEPSErrors.INTERNAL_ERROR.errorCode(),
					PEPSErrors.INTERNAL_ERROR.errorCode(),
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


    private AttributeStatement findAttributeStatement(final Assertion assertion) throws STORKSAMLEngineException{
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
            throw new STORKSAMLEngineException(PEPSErrors.INTERNAL_ERROR.errorCode(),
                    PEPSErrors.INTERNAL_ERROR.errorCode(),"AttributeStatement it's not present.");
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
	 * @throws STORKSAMLEngineException the STORKSAML engine exception
	 */
	private IPersonalAttributeList generatePersonalAttributeList(
			final Assertion assertion) throws STORKSAMLEngineException {
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
					throw new STORKSAMLEngineException(PEPSErrors.INTERNAL_ERROR.errorCode(),
                            PEPSErrors.INTERNAL_ERROR.errorCode(),"Attribute value it's unknown.");
				}
			}

			personalAttribute.setValue(simpleValues);
			personalAttribute.setComplexValue(multiValues);
			personalAttrList.add(personalAttribute);
		}

		return personalAttrList;
	}

	/**
	 * Generate stork authentication request.
	 * 
	 * @param request the request that contain all parameters for generate an
	 *            authentication request.
	 * 
	 * @return the STORK authentication request that has been processed.
	 * 
	 * @throws STORKSAMLEngineException the STORKSAML engine exception
	 */
	public STORKAuthnRequest generateSTORKAuthnRequest(
			final STORKAuthnRequest request) throws STORKSAMLEngineException {
		LOG.trace("Generate SAMLAuthnRequest.");
		if(request ==null){
			LOG.debug(SAML_EXCHANGE, "Sign and Marshall - null input");
			LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : Sign and Marshall -null input");
			throw new STORKSAMLEngineException(
					PEPSErrors.INTERNAL_ERROR.errorCode(),
					PEPSErrors.INTERNAL_ERROR.errorMessage());
		}
        selectFormat(request.getMessageFormatName());
        // Validate Parameters mandatories
		validateParamAuthnReq(request);

		final AuthnRequest authnRequestAux = SAMLEngineUtils
                .generateSAMLAuthnRequest(SAMLEngineUtils.generateNCName(),
                        SAMLVersion.VERSION_20, SAMLEngineUtils.getCurrentTime());

		// Set name spaces.
		setRequestNameSpaces(authnRequestAux);

		// Add parameter Mandatory STORK
		authnRequestAux.setForceAuthn(Boolean.TRUE);

		// Add parameter Mandatory STORK
		authnRequestAux.setIsPassive(Boolean.FALSE);

		authnRequestAux.setAssertionConsumerServiceURL(request.getAssertionConsumerServiceURL());

		authnRequestAux.setProviderName(request.getProviderName());

		// Add protocol binding
		authnRequestAux.setProtocolBinding(getProtocolBinding(request.getBinding()));

		// Add parameter optional STORK
		// Destination is mandatory if the destination is a C-PEPS
		// The application must to know if the destination is a C-PEPS.
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

		// Optional STORK
		final String formatEntity = super.getSamlCoreProperties()
		.getFormatEntity();
		if (StringUtils.isNotBlank(formatEntity)) {
			issuer.setFormat(formatEntity);
		}

		authnRequestAux.setIssuer(issuer);
		addAuthnContext(request, authnRequestAux);

		// Generate stork extensions.
		final Extensions storkExtensions =getExtensionProcessor().generateExtensions(this, request);
		// add the extensions to the SAMLAuthnRequest
		authnRequestAux.setExtensions(storkExtensions);
		addNameIDPolicy(authnRequestAux, request.getEidasNameidFormat());

		// the result contains an authentication request token (byte[]),
		// identifier of the token, and all parameters from the request.
		final STORKAuthnRequest authRequest = getExtensionProcessor().processExtensions(authnRequestAux
				.getExtensions());
        authRequest.setMessageFormatName(getExtensionProcessor().getFormat().getName());

		try {
			authRequest.setTokenSaml(super.signAndMarshall(authnRequestAux));
		} catch (SAMLEngineException e) {
			LOG.debug(SAML_EXCHANGE, "Sign and Marshall.", e);
			LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : Sign and Marshall.", e);
			throw new STORKSAMLEngineException(
					PEPSErrors.INTERNAL_ERROR.errorCode(),
					PEPSErrors.INTERNAL_ERROR.errorMessage(), e);
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

	private void addAuthnContext(final STORKAuthnRequest request, AuthnRequest authnRequestAux) throws STORKSAMLEngineException{
		if(StringUtils.isEmpty(request.getEidasLoA())) {
			return;
		}
		if( EidasLoaLevels.getLevel(request.getEidasLoA())==null){
			throw new STORKSAMLEngineException(PEPSErrors.COLLEAGUE_REQ_INVALID_LOA.errorCode(), PEPSErrors.COLLEAGUE_REQ_INVALID_LOA.errorMessage());
		}
		RequestedAuthnContext authnContext = (RequestedAuthnContext)SAMLEngineUtils.createSamlObject(RequestedAuthnContext.DEFAULT_ELEMENT_NAME);
		authnContext.setComparison(SAMLEngineUtils.getAuthnCtxtComparisonType(EidasLoaCompareType.getCompareType(request.getEidasLoACompareType())));
		AuthnContextClassRef authnContextClassRef = (AuthnContextClassRef)SAMLEngineUtils.createSamlObject(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
		authnContextClassRef.setAuthnContextClassRef(request.getEidasLoA());
		authnContext.getAuthnContextClassRefs().add(authnContextClassRef);
		authnRequestAux.setRequestedAuthnContext(authnContext);

	}
    public STORKAuthnResponse generateSTORKAuthnResponse(
            final STORKAuthnRequest request,
            final STORKAuthnResponse responseAuthReq, final String ipAddress,
            final boolean isHashing) throws STORKSAMLEngineException {
        return generateSTORKAuthnResponse(request, responseAuthReq, ipAddress,isHashing,false);
    }
	/**
	 * Generate stork authentication response.
	 * 
	 * @param request the request
	 * @param responseAuthReq the response authentication request
	 * @param ipAddress the IP address
     * @param isHashing the is hashing
     * @param signAssertion whether to sign the attribute assertion
	 *
	 * @return the sTORK authentication response
	 * 
	 * @throws STORKSAMLEngineException the STORKSAML engine exception
	 */
	public STORKAuthnResponse generateSTORKAuthnResponse(
			final STORKAuthnRequest request,
			final STORKAuthnResponse responseAuthReq, final String ipAddress,
			final boolean isHashing, final boolean signAssertion) throws STORKSAMLEngineException {
		LOG.trace("generateSTORKAuthnResponse");
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
                signedAssertion = (Assertion) super.sign(assertion);
            }catch(SAMLEngineException exc){
                LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : cannot sign assertion: {}", exc.getMessage());
                LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : cannot sign assertion: {}", exc);
            }
        }
		response.getAssertions().add(signedAssertion==null?assertion:signedAssertion);

		final STORKAuthnResponse authresponse = new STORKAuthnResponse();

		try {
			authresponse.setTokenSaml(super.signAndMarshall(response));
			authresponse.setSamlId(response.getID());
		} catch (SAMLEngineException e) {
			LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : Sign and Marshall.", e.getMessage());
			LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : Sign and Marshall.", e);
			throw new STORKSAMLEngineException(
					PEPSErrors.INTERNAL_ERROR.errorCode(),
                    PEPSErrors.INTERNAL_ERROR.errorMessage(),e);
		}
		return authresponse;
	}
	private void addAuthnContextClassRef(final STORKAuthnResponse responseAuthReq,final Assertion assertion){
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
	 * Generate stork authentication response fail.
	 * 
	 * @param request the request
	 * @param response the response
	 * @param ipAddress the IP address
	 * @param isHashing the is hashing
	 * 
	 * @return the sTORK authentication response
	 * 
	 * @throws STORKSAMLEngineException the STORKSAML engine exception
	 */
	public STORKAuthnResponse generateSTORKAuthnResponseFail(
			final STORKAuthnRequest request, final STORKAuthnResponse response,
			final String ipAddress, final boolean isHashing)
	throws STORKSAMLEngineException {
		LOG.trace("generateSTORKAuthnResponseFail");

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

		final STORKAuthnResponse storkResponse = new STORKAuthnResponse();

		try {
			storkResponse.setTokenSaml(super.signAndMarshall(responseFail));
			storkResponse.setSamlId(responseFail.getID());
		} catch (SAMLEngineException e) {
			LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : SAMLEngineException.", e.getMessage());
			LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : SAMLEngineException.", e);
			throw new STORKSAMLEngineException(PEPSErrors.INTERNAL_ERROR.errorCode(),
                    PEPSErrors.INTERNAL_ERROR.errorMessage(),e);
		}
		return storkResponse;
	}

	/**
	 * Generate stork authentication statement for the authentication statement.
	 * 
	 * @param ipAddress the IP address
	 * 
	 * @return the authentication statement
	 */
	private AuthnStatement generateStorkAuthStatement(final String ipAddress) {
		LOG.trace("Generate stork authenticate statement.");
		final SubjectLocality subjectLocality = SAMLEngineUtils
		.generateSubjectLocality(ipAddress);

		final AuthnContext authnContext = (AuthnContext) SAMLEngineUtils
		.createSamlObject(AuthnContext.DEFAULT_ELEMENT_NAME);

		final AuthnContextDecl authnContextDecl = (AuthnContextDecl) SAMLEngineUtils
		.createSamlObject(AuthnContextDecl.DEFAULT_ELEMENT_NAME);

		authnContext.setAuthnContextDecl(authnContextDecl);

		final AuthnStatement authnStatement = SAMLEngineUtils
		.generateAthnStatement(new DateTime(), authnContext);

		// Optional STORK
		authnStatement.setSessionIndex(null);
		authnStatement.setSubjectLocality(subjectLocality);

		return authnStatement;
	}


	/**
	 * Gets the alias from X.509 Certificate at keystore.
	 * 
	 * @param keyInfo the key info
	 * @param storkOwnKeyStore 
	 * @param storkOwnKeyStore 
	 * 
	 * @return the alias
	 */
    private String getAlias(final KeyInfo keyInfo, KeyStore storkOwnKeyStore) {

        LOG.trace("Recover alias information");

        String alias = null;
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

            final String tokenSerialNumber = cert.getSerialNumber().toString(HEXA);
            final X500Name tokenIssuerDN = new X500Name(cert.getIssuerDN().getName());


            String aliasCert;
            X509Certificate certificate;
            boolean find = false;

            for (final Enumeration<String> e = storkOwnKeyStore.aliases(); e
                    .hasMoreElements()
                    && !find; ) {
                aliasCert = e.nextElement();
                certificate = (X509Certificate) storkOwnKeyStore
                        .getCertificate(aliasCert);

                final String serialNum = certificate.getSerialNumber().toString(HEXA);

				X500Name issuerDN = new X500Name(certificate
                        .getIssuerDN().getName());

                if(serialNum.equalsIgnoreCase(tokenSerialNumber)
                        && X500PrincipalUtil.principalEquals(issuerDN, tokenIssuerDN)){
                    alias = aliasCert;
                    find = true;
                }

            }

        } catch (KeyStoreException e) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : Procces getAlias from certificate associated into the signing keystore..", e.getMessage());
            LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : Procces getAlias from certificate associated into the signing keystore..", e);
        } catch (CertificateException e) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : Procces getAlias from certificate associated into the signing keystore..", e.getMessage());
            LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : Procces getAlias from certificate associated into the signing keystore..", e);
        } catch (RuntimeException e) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : Procces getAlias from certificate associated into the signing keystore..", e.getMessage());
            LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : Procces getAlias from certificate associated into the signing keystore..", e);
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
	 * Sets the name spaces.
	 * 
	 * @param tokenSaml the new name spaces
	 */
	private void setRequestNameSpaces(final XMLObject tokenSaml) {
		LOG.trace("Set namespaces.");
        tokenSaml.getNamespaceManager().registerNamespace(new Namespace(SAMLConstants.SAML20_NS, SAMLConstants.SAML20_PREFIX));
        tokenSaml.getNamespaceManager().registerNamespace(new Namespace("http://www.w3.org/2000/09/xmldsig#", "ds"));
        tokenSaml.getNamespaceManager().registerNamespace(new Namespace(SAMLConstants.SAML20P_NS, SAMLConstants.SAML20P_PREFIX));
		tokenSaml.getNamespaceManager().registerNamespace(new Namespace(SAMLCore.STORK10_NS.getValue(), SAMLCore.STORK10_PREFIX.getValue()));
		tokenSaml.getNamespaceManager().registerNamespace(new Namespace(SAMLCore.STORK10P_NS.getValue(), SAMLCore.STORK10P_PREFIX.getValue()));
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
	 * @throws STORKSAMLEngineException the STORKSAML engine exception
	 */
	private void validateParamAuthnReq(final STORKAuthnRequest request)
	throws STORKSAMLEngineException {
		LOG.trace("Validate parameters from authentication request.");

		// URL to which Authentication Response must be sent.
		if (getExtensionProcessor().getFormat()==SAMLExtensionFormat.STORK10 && StringUtils.isBlank(request.getAssertionConsumerServiceURL())) {
			throw new STORKSAMLEngineException(PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"StorkSamlEngine: Assertion Consumer Service URL is mandatory.");
		}

		// the name of the original service provider requesting the
		// authentication.
		if (StringUtils.isBlank(request.getProviderName())) {
			throw new STORKSAMLEngineException(PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"StorkSamlEngine: Service Provider is mandatory.");
		}

		// object that contain all attributes requesting.
		if (request.getPersonalAttributeList() == null
				|| request.getPersonalAttributeList().isEmpty()) {
			throw new STORKSAMLEngineException(PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"attributeQueries is null or empty.");
		}

		// Quality authentication assurance level.
        int qaa=request.getQaa();
		if (getExtensionProcessor().getFormat()==SAMLExtensionFormat.STORK10 && ( qaa< QAAAttribute.MIN_VALUE)
				|| (qaa > QAAAttribute.MAX_VALUE)) {
			throw new STORKSAMLEngineException(PEPSErrors.QAALEVEL.errorCode(),
                    PEPSErrors.QAALEVEL.errorCode(),"Qaal: " + request.getQaa()+ ", is invalid.");
		}

	}


	/**
	 * Validate parameters from response.
	 * 
	 * @param request the request
	 * @param responseAuthReq the response authentication request
	 * 
	 * @throws STORKSAMLEngineException the STORKSAML engine exception
	 */
	private void validateParamResponse(final STORKAuthnRequest request,
			final STORKAuthnResponse responseAuthReq)
	throws STORKSAMLEngineException {
		LOG.trace("Validate parameters response.");
		if (StringUtils.isBlank(request.getIssuer())) {
			throw new STORKSAMLEngineException(PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"Issuer must be not empty or null.");
		}

		if (responseAuthReq.getPersonalAttributeList() == null
				|| responseAuthReq.getPersonalAttributeList().isEmpty()) {
			LOG.error(SAML_EXCHANGE, "PersonalAttributeList is null or empty.");
			throw new STORKSAMLEngineException(PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"PersonalAttributeList is null or empty.");
		}

		if (StringUtils.isBlank(request.getAssertionConsumerServiceURL())) {
			throw new STORKSAMLEngineException(PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"assertionConsumerServiceURL is null or empty.");
		}

		if (StringUtils.isBlank(request.getSamlId())) {
			throw new STORKSAMLEngineException(PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"request ID is null or empty.");
		}
		initResponseProcessor(request);
	}
	private void initResponseProcessor(final STORKAuthnRequest request){
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
	 * @throws STORKSAMLEngineException the STORKSAML engine exception
	 */
	private void validateParamResponseFail(final STORKAuthnRequest request,
			final STORKAuthnResponse response) throws STORKSAMLEngineException {
		LOG.trace("Validate parameters response fail.");
		if (StringUtils.isBlank(response.getStatusCode())) {
			throw new STORKSAMLEngineException(PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"Code error it's null or empty.");
		}

		if (StringUtils.isBlank(request.getAssertionConsumerServiceURL())) {
			throw new STORKSAMLEngineException(PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"assertionConsumerServiceURL is null or empty.");
		}

		if (StringUtils.isBlank(request.getSamlId())) {
			throw new STORKSAMLEngineException(PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"request ID is null or empty.");
		}
		initResponseProcessor(request);
	}

	/**
	 * Validate stork authentication request.
	 * 
	 * @param tokenSaml the token SAML
	 * 
	 * @return the sTORK authentication request
	 * 
	 * @throws STORKSAMLEngineException the STORKSAML engine exception
	 */
	public STORKAuthnRequest validateSTORKAuthnRequest(final byte[] tokenSaml)
	throws STORKSAMLEngineException {
		LOG.trace("validateSTORKAuthnRequest");

        if (tokenSaml == null) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : Saml authentication request is null.");
            throw new STORKSAMLEngineException(PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"Saml authentication request is null.");
        }
        validateSchema(new String(tokenSaml, Charset.forName("UTF-8")));

		final AuthnRequest samlRequest = validateRequestHelper(tokenSaml);
		LOG.trace("Generate STORKAuthnRequest.");
		final STORKAuthnRequest authnRequest = getExtensionProcessor().processExtensions(samlRequest.getExtensions());

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
        authnRequest.setBinding(SAMLEngineUtils.getStorkBindingMethod(samlRequest.getProtocolBinding()));
		authnRequest.setEidasNameidFormat(samlRequest.getNameIDPolicy()==null?null:samlRequest.getNameIDPolicy().getFormat());
        authnRequest.setMessageFormatName(getExtensionProcessor().getFormat().getName());

		//Delete unknown elements from requested ones
		final Iterator<PersonalAttribute> iterator = authnRequest.getPersonalAttributeList().iterator();
        IPersonalAttributeList cleanPerAttrList = (PersonalAttributeList) authnRequest.getPersonalAttributeList();
		while (iterator.hasNext()) {

			final PersonalAttribute attribute = iterator.next();

			// Verify if the attribute name exits.
			final String attributeName = getAttributeName(attribute.getName());

			if (StringUtils.isBlank(attributeName)) {
				LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : Attribute name: {} was not found. It will be removed from the request object", attribute.getName());
				cleanPerAttrList.remove(attribute.getName());
			}

		}	
		authnRequest.setPersonalAttributeList(cleanPerAttrList);

		return authnRequest;

	}

	private void extractLoA(AuthnRequest samlRequest, STORKAuthnRequest authnRequest) throws STORKSAMLEngineException{
		if(samlRequest.getRequestedAuthnContext()!=null && !samlRequest.getRequestedAuthnContext().getAuthnContextClassRefs().isEmpty()){
			RequestedAuthnContext rac = samlRequest.getRequestedAuthnContext();
			String comparison = rac.getComparison().toString();
			List<AuthnContextClassRef> authnContexts=rac.getAuthnContextClassRefs();
			for(AuthnContextClassRef contextRef:authnContexts) {
				EidasLoaLevels level = EidasLoaLevels.getLevel(contextRef.getAuthnContextClassRef());
				if (level != null) {
					authnRequest.setEidasLoA(level.stringValue());
					authnRequest.setEidasLoACompareType(EidasLoaCompareType.getCompareType(comparison).stringValue());
					break;
				}else if(!StringUtils.isEmpty(contextRef.getAuthnContextClassRef())){
					throw new STORKSAMLEngineException(PEPSErrors.INVALID_LOA_VALUE.errorCode(),
							PEPSErrors.INVALID_LOA_VALUE.errorMessage());
				}
			}
		}
	}
    private AuthnRequest validateRequestHelper(final byte[] tokenSaml) throws STORKSAMLEngineException{
        LOG.trace("Validate AuthnRequest");
		AuthnRequest samlRequest=null;
        ExtensionProcessorI currentProcessor=null;
        try {
            if(extensionProcessor!=null) {
                samlRequest = validateRequestHelper(extensionProcessor, tokenSaml);
            }

            for(int i=0;samlRequest==null && i<getExtensionProcessors().length;i++){
				ExtensionProcessorI trialExtensionProcessor=getExtensionProcessors()[i];
				samlRequest=validateRequestHelper(trialExtensionProcessor, tokenSaml);
            }
        }catch(STORKSAMLEngineException e){
			throw e;
		}catch (Exception e) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : ValidationException: validate AuthRequest.", e.getMessage());
            LOG.debug("ValidationException: validate AuthRequest.", e);
            throw new STORKSAMLEngineException(PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    PEPSErrors.MESSAGE_VALIDATION_ERROR.errorMessage(),e);
        }
        if(samlRequest==null){
			setExtensionProcessor(currentProcessor);
            throw new STORKSAMLEngineException(PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
					PEPSErrors.MESSAGE_VALIDATION_ERROR.errorMessage());
        }
		return samlRequest;
    }

	private AuthnRequest validateRequestHelper(ExtensionProcessorI extensionProcessor, final byte[] tokenSaml) throws STORKSAMLEngineException{
		AuthnRequest samlRequest=null;
		ValidatorSuite suite = Configuration.getValidatorSuite(extensionProcessor.getRequestValidatorId());
		extensionProcessor.configureExtension();
		samlRequest = (AuthnRequest) validateStorkSaml(tokenSaml);
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
            samlRequest=null;
		}
		return samlRequest;
	}

	private String getAttributeName(String name){
		String attributeName = getSamlCoreProperties().getProperty(getExtensionProcessor().namePrefix()+name);

		if(StringUtils.isBlank(attributeName)) {
			attributeName = getSamlCoreProperties().getProperty(name);
		}
		return attributeName;
	}

    private Response computeAuxResponse(final byte[] tokenSaml)throws STORKSAMLEngineException{
        Response samlResponseAux = null;
        try {
            samlResponseAux = (Response) validateStorkSaml(tokenSaml);
            if(decryptResponse()) {
                /*
                    In the @eu.stork.encryption.SAMLAuthnResponseDecrypter.decryptSAMLResponse method when inserting
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

    private void validateSamlResponse(final Response samlResponse)throws STORKSAMLEngineException{
        LOG.trace("Validate AuthnResponse");
        ValidatorSuite suite = Configuration.getValidatorSuite(getExtensionProcessor().getResponseValidatorId());
        try {
            suite.validate(samlResponse);
        } catch (ValidationException e) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : ValidationException: validate AuthResponse.", e.getMessage());
            LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : ValidationException: validate AuthResponse.", e);
            throw new STORKSAMLEngineException(PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    PEPSErrors.MESSAGE_VALIDATION_ERROR.errorMessage(),e);
        } catch (Exception e) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : ValidationException: validate AuthResponse.", e.getMessage());
            LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : ValidationException: validate AuthResponse.", e);
            throw new STORKSAMLEngineException(PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    PEPSErrors.MESSAGE_VALIDATION_ERROR.errorMessage(),e);
        }

    }
    private STORKAuthnResponse createStorkResponse(final Response samlResponse){
        LOG.trace("Create StorkAuthResponse.");
        final STORKAuthnResponse authnResponse = new STORKAuthnResponse();

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
	 * Validate stork authentication response.
	 * 
	 * @param tokenSaml the token SAML
	 * @param userIP the user IP
	 * 
	 * @return the Stork authentication response
	 * 
	 * @throws STORKSAMLEngineException the STORKSAML engine exception
	 */
    public STORKAuthnResponse validateSTORKAuthnResponse(
			final byte[] tokenSaml, final String userIP, final long skewTimeInMillis)
	throws STORKSAMLEngineException {
        LOG.trace("validateSTORKAuthnResponse");

        if (tokenSaml == null) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : Saml authentication response is null.");
            throw new STORKSAMLEngineException(PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"Saml authentication response is null.");
        }

        validateSchema(new String(tokenSaml, Charset.forName("UTF-8")));

        final Response samlResponse = computeAuxResponse(tokenSaml);

        validateSamlResponse(samlResponse);

        final STORKAuthnResponse authnResponse = createStorkResponse(samlResponse);
		LOG.trace("validateStorkResponse");
		final Assertion assertion = validateStorkResponse(samlResponse, userIP, skewTimeInMillis);
		
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
	 * Validate stork response.
	 * 
	 * @param samlResponse the SAML response
	 * @param userIP the user IP
	 * 
	 * @return the assertion
	 * 
	 * @throws STORKSAMLEngineException the STORKSAML engine exception
	 */
	private Assertion validateStorkResponse(final Response samlResponse, final String userIP, final Long skewTimeInMillis) throws STORKSAMLEngineException {
		// Exist only one Assertion
		if (samlResponse.getAssertions() == null || samlResponse.getAssertions().isEmpty()) {
            //in replace of throwing  STORKSAMLEngineException("Assertion is null or empty.")
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

    private void verifyConditions(Assertion assertion) throws STORKSAMLEngineException {
        Conditions conditions = assertion.getConditions();
        final DateTime serverDate = clock.getCurrentTime();
        LOG.debug("serverDate            : " + serverDate);

        if (conditions.getAudienceRestrictions() == null || conditions.getAudienceRestrictions().isEmpty()) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : AudienceRestriction must be present");
            throw new STORKSAMLEngineException(PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"AudienceRestriction must be present");
        }
        if (conditions.getOneTimeUse() == null) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : OneTimeUse must be present");
            throw new STORKSAMLEngineException(PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"OneTimeUse must be present");
        }
        if (conditions.getNotBefore() == null) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : NotBefore must be present");
            throw new STORKSAMLEngineException(PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"NotBefore must be present");
        }
        if (conditions.getNotBefore().isAfter(serverDate)) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : Current time is before NotBefore condition");
            throw new STORKSAMLEngineException(PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"Current time is before NotBefore condition");
        }
        if (conditions.getNotOnOrAfter() == null) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : NotOnOrAfter must be present");
            throw new STORKSAMLEngineException(PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"NotOnOrAfter must be present");
        }
        if (conditions.getNotOnOrAfter().isBeforeNow()) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : Current time is after NotOnOrAfter condition");
            throw new STORKSAMLEngineException(PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"Current time is after NotOnOrAfter condition");
        }
        if (assertion.getConditions().getNotOnOrAfter().isBefore(serverDate)) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : Token date expired (getNotOnOrAfter =  " + assertion.getConditions().getNotOnOrAfter() + ", server_date: " + serverDate + ")");
            throw new STORKSAMLEngineException(PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"Token date expired (getNotOnOrAfter =  " + assertion.getConditions().getNotOnOrAfter() + " ), server_date: " + serverDate);
        }
    }

    private void verifyMethodBearer(String userIP, Assertion assertion) throws STORKSAMLEngineException {
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
                        throw new STORKSAMLEngineException(PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                                PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"browser_ip is null or empty.");
                    } else if (StringUtils.isBlank(element.getSubjectConfirmationData().getAddress())) {
                        LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : token_ip attribute is null or empty.");
                        throw new STORKSAMLEngineException(PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                                PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"token_ip attribute is null or empty.");
                    }
                }
                final boolean ipEqual = element.getSubjectConfirmationData().getAddress().equals(userIP);
                // Validation ipUser
                if (!ipEqual && ipValidate) {
                    LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : SubjectConfirmation BEARER: IPs doesn't match : token_ip [{}] browser_ip [{}]", element.getSubjectConfirmationData().getAddress(), userIP);
                    throw new STORKSAMLEngineException(PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                            PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"IPs doesn't match : token_ip ("+ element.getSubjectConfirmationData().getAddress() + ") browser_ip ("+ userIP + ")");
                }
            }

        }
    }

    private void validateAssertionsSignature(Response samlObject) throws STORKSAMLEngineException {
        try{
            for(Assertion a:samlObject.getAssertions()){
                if(a.isSigned()){
                    super.validateSignature(a);
                }
            }
        }catch(SAMLEngineException e){
            STORKSAMLEngineException exc = new STORKSAMLEngineException(PEPSErrors.INVALID_ASSERTION_SIGNATURE.errorCode(), PEPSErrors.INVALID_ASSERTION_SIGNATURE.errorMessage(), e);
            throw exc;
        }


    }

    private SignableSAMLObject validateStorkSamlSignature(SignableSAMLObject samlObject)throws STORKSAMLEngineException{
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
						throw new SAMLEngineException(PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"");
				}
                if (samlObject instanceof Response){
                    setCountryResponseFrom(getCountry(samlObject.getSignature().getKeyInfo()));
                    LOG.debug(SAML_EXCHANGE, "Response received from country: " + getCountryResponseFrom());
                }
                validSamlObject = (SignableSAMLObject)super.validateSignature(samlObject);
                if (samlObject instanceof Response){
                    //check assertions signature, if any
                    validateAssertionsSignature((Response)samlObject);
                }
            } catch (SAMLEngineException e) {
                LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : SAMLEngineException validateSignature.", e.getMessage());
                LOG.debug(SAML_EXCHANGE, "SAMLEngineException validateSignature.", e);
                STORKSAMLEngineException exc = new STORKSAMLEngineException(e);
                if(PEPSErrors.isErrorCode(e.getMessage())){
                    exc.setErrorCode(e.getMessage());
                }
				if(PEPSErrors.isErrorCode(e.getErrorCode())){
					exc.setErrorCode(e.getErrorCode());
				}
                throw exc;
            }
        }
        return  validSamlObject;
    }
    /**
	 * Validate stork SAML.
	 * 
	 * @param tokenSaml the token SAML
	 * 
	 * @return the signable SAML object
	 * 
	 * @throws STORKSAMLEngineException the STORKSAML engine exception
	 */
	private SignableSAMLObject validateStorkSaml(final byte[] tokenSaml) throws STORKSAMLEngineException {

		LOG.trace("Validate StorkSaml message.");

		if (tokenSaml == null) {
			LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : Saml authentication request is null.");
			throw new STORKSAMLEngineException(PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),"Saml authentication request is null.");
		}

		LOG.trace("Generate AuthnRequest from request.");
		SignableSAMLObject samlObject;

		try {
			samlObject = (SignableSAMLObject) super.unmarshall(tokenSaml);
		} catch (SAMLEngineException e) {
			LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : SAMLEngineException unmarshall.", e.getMessage());
			LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : SAMLEngineException unmarshall.", e);
			throw new STORKSAMLEngineException(PEPSErrors.INVALID_ENCRYPTION_ALGORITHM.errorCode(),
                    PEPSErrors.INVALID_ENCRYPTION_ALGORITHM.errorMessage(),e);
		}
        samlObject = validateStorkSamlSignature(samlObject);
        LOG.trace("Validate Schema.");
		final ValidatorSuite validatorSuite = Configuration.getValidatorSuite("saml2-core-schema-validator");
		try {
			validatorSuite.validate(samlObject);
		} catch (ValidationException e) {
			LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : ValidationException.", e.getMessage());
			LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : ValidationException.", e);
			throw new STORKSAMLEngineException(PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode(),
                    PEPSErrors.MESSAGE_VALIDATION_ERROR.errorMessage(),e);
		}

		return samlObject;
	}
    /**
     * @deprecated
     */
    @Deprecated
    public STORKAuthnRequest generateSTORKAuthnRequestWithoutValidation(
            final STORKAuthnRequest request) throws STORKSAMLEngineException {
        LOG.trace("Generate SAMLAuthnRequest.");

        // Validate Parameters mandatories
		selectFormat(request.getMessageFormatName());

        final AuthnRequest authnRequestAux = SAMLEngineUtils
                .generateSAMLAuthnRequest(SAMLEngineUtils.generateNCName(),
                        SAMLVersion.VERSION_20, SAMLEngineUtils
                        .getCurrentTime());

        // Set name spaces.
        setRequestNameSpaces(authnRequestAux);

        // Add parameter Mandatory STORK
        authnRequestAux.setForceAuthn(Boolean.TRUE);

        // Add parameter Mandatory STORK
        authnRequestAux.setIsPassive(Boolean.FALSE);

        authnRequestAux.setAssertionConsumerServiceURL(request
                .getAssertionConsumerServiceURL());

        authnRequestAux.setProviderName(request.getProviderName());

        // Add protocol binding
        authnRequestAux.setProtocolBinding(getProtocolBinding(request.getBinding()));

        // Add parameter optional STORK
        // Destination is mandatory if the destination is a C-PEPS
        // The application must to know if the destination is a C-PEPS.
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

        // Optional STORK
        final String formatEntity = super.getSamlCoreProperties()
                .getFormatEntity();
        if (StringUtils.isNotBlank(formatEntity)) {
            issuer.setFormat(formatEntity);
        }

        authnRequestAux.setIssuer(issuer);

        // Generate stork extensions.
        final Extensions storkExtensions = getExtensionProcessor().generateExtensions(this, request);
        // add the extensions to the SAMLAuthnRequest
        authnRequestAux.setExtensions(storkExtensions);

        // the result contains an authentication request token (byte[]),
        // identifier of the token, and all parameters from the request.
        final STORKAuthnRequest authRequest = getExtensionProcessor().processExtensions(authnRequestAux
				.getExtensions());

        try {
            authRequest.setTokenSaml(super.signAndMarshall(authnRequestAux));
        } catch (SAMLEngineException e) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : Sign and Marshall.", e.getMessage());
            LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : Sign and Marshall.", e);
            throw new STORKSAMLEngineException(
					PEPSUtil.getConfig(PEPSErrors.INTERNAL_ERROR.errorCode()),
					PEPSUtil.getConfig(PEPSErrors.INTERNAL_ERROR.errorMessage()), e);
        }

        authRequest.setSamlId(authnRequestAux.getID());
        authRequest.setDestination(authnRequestAux.getDestination());
        authRequest.setAssertionConsumerServiceURL(authnRequestAux
                .getAssertionConsumerServiceURL());

        authRequest.setProviderName(authnRequestAux.getProviderName());
        authRequest.setIssuer(authnRequestAux.getIssuer().getValue());

        return authRequest;
    }

    public STORKAuthnRequest generateSTORKAuthnRequestWithoutSIgn(
            final STORKAuthnRequest request) throws STORKSAMLEngineException {
        LOG.trace("Generate SAMLAuthnRequest.");

        // Validate Parameters mandatories

        final AuthnRequest authnRequestAux = SAMLEngineUtils
                .generateSAMLAuthnRequest(SAMLEngineUtils.generateNCName(),
                        SAMLVersion.VERSION_20, SAMLEngineUtils
                        .getCurrentTime());

        // Set name spaces.
        setRequestNameSpaces(authnRequestAux);

        // Add parameter Mandatory STORK
        authnRequestAux.setForceAuthn(Boolean.TRUE);

        // Add parameter Mandatory STORK
        authnRequestAux.setIsPassive(Boolean.FALSE);

        authnRequestAux.setAssertionConsumerServiceURL(request
                .getAssertionConsumerServiceURL());

        authnRequestAux.setProviderName(request.getProviderName());

        // Add protocol binding
        authnRequestAux.setProtocolBinding(super.getSamlCoreProperties()
                .getProtocolBinding());

        // Add parameter optional STORK
        // Destination is mandatory if the destination is a C-PEPS
        // The application must to know if the destination is a C-PEPS.
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

        // Optional STORK
        final String formatEntity = super.getSamlCoreProperties()
                .getFormatEntity();
        if (StringUtils.isNotBlank(formatEntity)) {
            issuer.setFormat(formatEntity);
        }

        authnRequestAux.setIssuer(issuer);

        // Generate stork extensions.
        final Extensions storkExtensions = getExtensionProcessor().generateExtensions(this, request);
        // add the extensions to the SAMLAuthnRequest
        authnRequestAux.setExtensions(storkExtensions);

        // the result contains an authentication request token (byte[]),
        // identifier of the token, and all parameters from the request.
        final STORKAuthnRequest authRequest = getExtensionProcessor().processExtensions(authnRequestAux
				.getExtensions());

        try {
            authRequest.setTokenSaml(super.noSignAndMarshall(authnRequestAux));
        } catch (SAMLEngineException e) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : Sign and Marshall.", e.getMessage());
            LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : Sign and Marshall.", e);
            throw new STORKSAMLEngineException(
					PEPSErrors.INTERNAL_ERROR.errorCode(),
					PEPSErrors.INTERNAL_ERROR.errorMessage(), e);
        }

        authRequest.setSamlId(authnRequestAux.getID());
        authRequest.setDestination(authnRequestAux.getDestination());
        authRequest.setAssertionConsumerServiceURL(authnRequestAux
                .getAssertionConsumerServiceURL());

        authRequest.setProviderName(authnRequestAux.getProviderName());
        authRequest.setIssuer(authnRequestAux.getIssuer().getValue());

        return authRequest;
    }
    public static String validateSchema(String samlRequestXML) throws STORKSAMLEngineException {
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
                throw new STORKSAMLEngineException(PEPSUtil.getConfig(PEPSErrors.DOC_TYPE_NOT_ALLOWED.errorCode()),
						PEPSErrors.DOC_TYPE_NOT_ALLOWED.errorCode(), "SAML request contains a DOCTYPE which is not allowed for security reason");
            } else {
                throw new STORKSAMLEngineException(PEPSUtil.getConfig(PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode()),
						PEPSErrors.MESSAGE_VALIDATION_ERROR.errorMessage(), e);
            }
        } catch (SAXException e) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : Validate schema exception", e.getMessage());
            LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : Validate schema exception", e);
            throw new STORKSAMLEngineException(PEPSUtil.getConfig(PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode()),
					PEPSErrors.MESSAGE_VALIDATION_ERROR.errorMessage(), e);
        } catch (IOException e) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : Validate schema exception", e.getMessage());
            LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : Validate schema exception", e);
            throw new STORKSAMLEngineException(PEPSUtil.getConfig(PEPSErrors.MESSAGE_VALIDATION_ERROR.errorCode()),
					PEPSErrors.MESSAGE_VALIDATION_ERROR.errorMessage(), e);
        }
        return samlRequestXML;
    }

    /**
	 * Resign authentication request ( for validation purpose).
	 * @return the resigned request
	 * @throws STORKSAMLEngineException the STORKSAML engine exception
	 */
	public STORKAuthnRequest resignSTORKAuthnRequest(final STORKAuthnRequest request, boolean changeProtocol) throws STORKSAMLEngineException {
        LOG.trace("Generate SAMLAuthnRequest.");

        STORKAuthnRequest authRequest = null;
        AuthnRequest authnRequestAux = null;

        try {
            authRequest = (STORKAuthnRequest) request.clone();
        } catch (CloneNotSupportedException e) {
            LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : Clone not supported in resignSTORKAuthnRequest {}", e);
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : Clone not supported in resignSTORKAuthnRequest {}", e.getMessage());
        }

        byte[] tokenSaml  = request.getTokenSaml() ;

        try {
            authnRequestAux = (AuthnRequest) unmarshall(tokenSaml);
            if(authnRequestAux.getProtocolBinding()==null || changeProtocol) {
				authnRequestAux.setProtocolBinding(getProtocolBinding(authRequest.getBinding()));
			}
        } catch (SAMLEngineException e) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : resignSTORKAuthnRequest {}", e.getMessage());
            LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : resignSTORKAuthnRequest {}", e);
        }

        try {
            authRequest.setTokenSaml(super.signAndMarshall(authnRequestAux));
        } catch (SAMLEngineException e) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : resignSTORKAuthnRequest : Sign and Marshall.", e.getMessage());
            LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : resignSTORKAuthnRequest : Sign and Marshall.", e);
            throw new STORKSAMLEngineException(PEPSErrors.INTERNAL_ERROR.errorCode(),
                    PEPSErrors.INTERNAL_ERROR.errorMessage(),e);
        }
        return authRequest;
    }
    public STORKAuthnRequest resignSTORKAuthnRequest(final STORKAuthnRequest request) throws STORKSAMLEngineException {
        return resignSTORKAuthnRequest(request,false);
    }
     /**
     * Resign tokenSaml ( for validation purpose).
     * @return the resigned request
     * @throws STORKSAMLEngineException the STORKSAML engine exception
     */
    public byte[] resignSTORKTokenSAML(final byte[] tokenSaml) throws STORKSAMLEngineException {
        LOG.trace("Generate SAMLAuthnRequest.");

        AuthnRequest authnRequestAux = null;

        try {
            authnRequestAux = (AuthnRequest) unmarshall(tokenSaml);
        } catch (SAMLEngineException e) {
            LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : unmarshall {}", e);
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : unmarshall {}", e.getMessage());
        }
        if(authnRequestAux==null){
            throw new STORKSAMLEngineException(PEPSErrors.INTERNAL_ERROR.errorCode(),
                    PEPSErrors.INTERNAL_ERROR.errorCode(), "invalid AuthnRequest");
        }

        try {
            return super.signAndMarshall(authnRequestAux);
        } catch (SAMLEngineException e) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : resignSTORKTokenSAML : Sign and Marshall.", e);
            LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : resignSTORKTokenSAML : Sign and Marshall.", e.getMessage());
            throw new STORKSAMLEngineException(PEPSErrors.INTERNAL_ERROR.errorCode(),
                    PEPSErrors.INTERNAL_ERROR.errorMessage(),e);
        }
    }

    /**
     * Resigns the saml token checking previously if it is encrypted
     * @param tokenSaml
     * @return
     * @throws STORKSAMLEngineException
     */
    public byte[] checkAndResignSTORKTokenSAML(final byte[] tokenSaml) throws STORKSAMLEngineException {

        SignableSAMLObject samlObject = null;

        try {
            samlObject = (SignableSAMLObject) unmarshall(tokenSaml);
            samlObject = validateStorkSamlSignature(samlObject);
        } catch (SAMLEngineException e) {
            LOG.info(SAML_EXCHANGE, "BUSINESS EXCEPTION : unmarshall {}", e.getMessage());
            LOG.debug(SAML_EXCHANGE, "BUSINESS EXCEPTION : unmarshall {}", e);
        }
        if(samlObject==null){
            throw new STORKSAMLEngineException(PEPSErrors.INTERNAL_ERROR.errorCode(),
                    PEPSErrors.INTERNAL_ERROR.errorMessage(),"BUSINESS EXCEPTION : invalid AuthnRequest");
        }

        try {
            return super.signAndMarshall(samlObject);
        } catch (SAMLEngineException e) {
            LOG.debug(SAML_EXCHANGE,"BUSINESS EXCEPTION : checkAndResignSTORKTokenSAML : Sign and Marshall.", e);
            LOG.info(SAML_EXCHANGE,"BUSINESS EXCEPTION : checkAndResignSTORKTokenSAML : Sign and Marshall.", e.getMessage());
            throw new STORKSAMLEngineException(
					PEPSErrors.INTERNAL_ERROR.errorCode(),
					PEPSErrors.INTERNAL_ERROR.errorMessage(), e);
        }
	}

	/**
	 * Returns true when the input contains an encrypted SAML Response
	 * @param tokenSaml
	 * @return
	 * @throws STORKSAMLEngineException
	 */
	public boolean isEncryptedSamlResponse(final byte[] tokenSaml) throws STORKSAMLEngineException {
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
        if(STORKAuthnRequest.BINDING_REDIRECT.equalsIgnoreCase(binding)) {
            return SAMLConstants.SAML2_REDIRECT_BINDING_URI;
        }else if(STORKAuthnRequest.BINDING_POST.equalsIgnoreCase(binding)){
            return SAMLConstants.SAML2_POST_BINDING_URI;
        }else if(STORKAuthnRequest.BINDING_EMPTY.equalsIgnoreCase(binding)){
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
		ExtensionProcessorI returnedExtensionProcessors[]=new ExtensionProcessorI[2];
		System.arraycopy(availableExtensionProcessors, 0, returnedExtensionProcessors, 0,availableExtensionProcessors.length);
		return returnedExtensionProcessors;
	}

    /**
     * init supported format from the requested attributes
     * Implementation note: currently, the set of supported attributes names for each format should be disjunct
     * @param attlist
     */
    public void initRequestedAttributes(Iterable<PersonalAttribute> attlist){
        Set<String> []supportedAttrSets=new Set[]{new HashSet<String>(EIDASAttributes.ATTRIBUTES_SET_NAMES.values()), new HashSet<String>(STORKAttributes.ATTRIBUTES_SET_NAMES.values())};
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
            STORKAuthnRequest request =extensionProcessor.processExtensions(samlRequest.getExtensions());
            //format discriminator goes here
            if(request!=null){
                return extensionProcessor.isValidRequest(samlRequest);
            }
        }catch(STORKSAMLEngineException e){
            throw new ValidationException(e);
        }
        return false;
    }

}
