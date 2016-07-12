/* 
 * Licensed under the EUPL, Version 1.1 or â€“ as soon they will be approved by
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

package eu.eidas.engine.test.simple;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

import eu.eidas.auth.commons.IPersonalAttributeList;
import eu.eidas.auth.commons.EIDASUtil;
import eu.eidas.auth.commons.PersonalAttribute;
import eu.eidas.auth.commons.PersonalAttributeList;
import eu.eidas.auth.commons.EIDASAuthnRequest;
import eu.eidas.auth.commons.EIDASAuthnResponse;
import eu.eidas.auth.commons.EIDASStatusCode;
import eu.eidas.auth.commons.EIDASSubStatusCode;
import eu.eidas.auth.engine.EIDASSAMLEngine;
import eu.eidas.auth.engine.core.stork.StorkExtensionProcessor;
import eu.eidas.engine.exceptions.EIDASSAMLEngineException;

import org.junit.Test;
import org.opensaml.xml.parse.BasicParserPool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The Class AuthRequestTest.
 */
public class EidasResponseTest {
    
    /** The engine. */
    private static EIDASSAMLEngine engine = null;
	static{
		try{
			engine = EIDASSAMLEngine.createSAMLEngine("CONF1");
			engine.setExtensionProcessor(new StorkExtensionProcessor());
		}catch(EIDASSAMLEngineException e){
			fail("Failed to initialize SAMLEngines");
		}
	}

    /**
     * Gets the engine.
     * 
     * @return the engine
     */
    public static EIDASSAMLEngine getEngine() {
        return engine;
    }

    /**
     * Sets the engine.
     * 
     * @param newEngine the new engine
     */
    public static void setEngine(final EIDASSAMLEngine newEngine) {
        EidasResponseTest.engine = newEngine;
    }

    /** The destination. */
    private static String destination;

    /** The service provider name. */
    private static String spName;

    /** The service provider sector. */
    private static String spSector;

    /** The service provider institution. */
    private static String spInstitution;

    /** The service provider application. */
    private static String spApplication;

    /** The service provider country. */
    private static String spCountry;
    
    /** The service provider id. */
    private static String spId;

    /** The quality authentication assurance level. */
    private static final int QAAL = 3;

    /** The state. */
    private static String state = "ES";
    
    /** The town. */
    private static String town = "Madrid";
    
    /** The municipality code. */
    private static String municipalityCode = "MA001";
    
    /** The postal code. */
    private static String postalCode = "28038";
    
    /** The street name. */
    private static String streetName = "Marchamalo";
    
    /** The street number. */
    private static String streetNumber = "3";
    
    /** The apartament number. */
    private static String apartamentNumber = "5º E";

    /** The List of Personal Attributes. */
    private static IPersonalAttributeList pal;

    /** The assertion consumer URL. */
    private static String assertConsumerUrl;

    /** The authentication request. */
    private static byte[] authRequest;

    /** The authentication response. */
    private static byte[] authResponse;

    /** The authentication request. */
    private static EIDASAuthnRequest authenRequest;

    /** The authentication response. */
    private static EIDASAuthnResponse authnResponse;

    /** The Constant LOG. */
    private static final Logger LOG = LoggerFactory
	    .getLogger(EidasResponseTest.class.getName());

    /**
     * Instantiates a new EIDAS response test.
     */
    public EidasResponseTest() {
	super();
    }

    /** The IP address. */
    private static String ipAddress;

    /** The is hashing. */
    private final boolean isHashing = Boolean.TRUE;

    /** The is not hashing. */
    private final boolean isNotHashing = Boolean.FALSE;

    /** The ERROR text. */
    private static final String ERROR_TXT = "generateAuthnResponse(...) should've thrown an EIDASSAMLEngineException!";


    /** Parser manager used to parse XML. */
    private static BasicParserPool parser;
    
    

    static {
	parser = EIDASSAMLEngine.getNewBasicSecuredParserPool();

	pal = new PersonalAttributeList();

	PersonalAttribute isAgeOver = new PersonalAttribute();
	isAgeOver.setName("isAgeOver");
	isAgeOver.setIsRequired(false);
	ArrayList<String> ages = new ArrayList<String>();
	ages.add("16");
	ages.add("18");
	isAgeOver.setValue(ages);
	pal.add(isAgeOver);

	PersonalAttribute dateOfBirth = new PersonalAttribute();
	dateOfBirth.setName("dateOfBirth");
	dateOfBirth.setIsRequired(false);
	pal.add(dateOfBirth);

	PersonalAttribute eIDNumber = new PersonalAttribute();
	eIDNumber.setName("eIdentifier");
	eIDNumber.setIsRequired(true);
	pal.add(eIDNumber);

	final PersonalAttribute givenName = new PersonalAttribute();
	givenName.setName("givenName");
	givenName.setIsRequired(true);
	pal.add(givenName);

	PersonalAttribute canRessAddress = new PersonalAttribute();
	canRessAddress.setName("canonicalResidenceAddress");
	canRessAddress.setIsRequired(true);
	pal.add(canRessAddress);

	

	destination = "http://proxyservice.gov.xx/EidasNode/ColleagueRequest";
	assertConsumerUrl = "http://connector.gov.xx/EidasNode/ColleagueResponse";
	spName = "University Oxford";
	
	spName = "University of Oxford";
	spSector = "EDU001";
	spInstitution = "OXF001";
	spApplication = "APP001";
	spCountry = "EN";
	
	spId = "EDU001-APP001-APP001";

	final EIDASAuthnRequest request = new EIDASAuthnRequest();
	request.setDestination(destination);
	request.setProviderName(spName);
	request.setQaa(QAAL);
	request.setPersonalAttributeList(pal);
	request.setAssertionConsumerServiceURL(assertConsumerUrl);

	// news parameters
	request.setSpSector(spSector);
	request.setSpInstitution(spInstitution);
	request.setSpApplication(spApplication);
	request.setSpCountry(spCountry);
	request.setSPID(spId);
	request.setCitizenCountryCode("ES");

	try {
	    authRequest = getEngine().generateEIDASAuthnRequest(request)
		    .getTokenSaml();
	    	    
	    authenRequest = getEngine().validateEIDASAuthnRequest(authRequest);
	    
	} catch (EIDASSAMLEngineException e) {
	    fail("Error create EIDASAuthnRequest");
	}

	ipAddress = "111.222.333.444";

	pal = new PersonalAttributeList();

	isAgeOver = new PersonalAttribute();
	isAgeOver.setName("isAgeOver");
	isAgeOver.setIsRequired(true);
	ages = new ArrayList<String>();

	ages.add("16");
	ages.add("18");

	isAgeOver.setValue(ages);
	isAgeOver.setStatus(EIDASStatusCode.STATUS_AVAILABLE.toString());
	pal.add(isAgeOver);

	dateOfBirth = new PersonalAttribute();
	dateOfBirth.setName("dateOfBirth");
	dateOfBirth.setIsRequired(false);
	final ArrayList<String> date = new ArrayList<String>();
	date.add("16/12/2008");
	dateOfBirth.setValue(date);
	dateOfBirth.setStatus(EIDASStatusCode.STATUS_AVAILABLE.toString());
	pal.add(dateOfBirth);

	eIDNumber = new PersonalAttribute();
	eIDNumber.setName("eIdentifier");
	eIDNumber.setIsRequired(true);
	final ArrayList<String> idNumber = new ArrayList<String>();
	idNumber.add("123456789PÑ");
	eIDNumber.setValue(idNumber);
	eIDNumber.setStatus(EIDASStatusCode.STATUS_AVAILABLE.toString());
	pal.add(eIDNumber);

	canRessAddress = new PersonalAttribute();
	canRessAddress.setName("canonicalResidenceAddress");
	canRessAddress.setIsRequired(true);
	canRessAddress.setStatus(EIDASStatusCode.STATUS_AVAILABLE.toString());
	final HashMap<String, String> address = new HashMap<String, String>();

	address.put("state", state);
	address.put("municipalityCode", municipalityCode);
	address.put("town", town);
	address.put("postalCode", postalCode);
	address.put("streetName", streetName);
	address.put("streetNumber", streetNumber);
	address.put("apartamentNumber", apartamentNumber);

	canRessAddress.setComplexValue(address);
	pal.add(canRessAddress);
    }

    /**
     * Test generate authentication request without errors.
     * 
     * @throws EIDASSAMLEngineException the EIDASSAML engine exception
     */
    @Test
    public final void testGenerateAuthnResponse() throws EIDASSAMLEngineException {

	final EIDASAuthnResponse response = new EIDASAuthnResponse();
	response.setPersonalAttributeList(pal);

	final EIDASAuthnResponse eidasResponse = getEngine()
		.generateEIDASAuthnResponse(authenRequest, response, ipAddress,
			isNotHashing);

	authResponse = eidasResponse.getTokenSaml();
	
	LOG.info("RESPONSE: " + SSETestUtils.encodeSAMLToken(authResponse));
	
	
    }

    /**
     * Test validation id parameter mandatory.
     */
    @Test
    public final void testResponseMandatoryId() {
	final String identifier = authenRequest.getSamlId();
	authenRequest.setSamlId(null);

	final EIDASAuthnResponse response = new EIDASAuthnResponse();
	response.setPersonalAttributeList(pal);

	try {
	    getEngine().generateEIDASAuthnResponse(authenRequest, response,
		    ipAddress, isHashing);
	    fail(ERROR_TXT);
	} catch (EIDASSAMLEngineException e) {
	    authenRequest.setSamlId(identifier);
	    LOG.error("Error");
	}
    }

    /**
     * Test generate authentication response in response to err1.
     */
    @Test
    public final void testResponseMandatoryIssuer() {

	final String issuer = authenRequest.getIssuer();
	authenRequest.setIssuer(null);

	final EIDASAuthnResponse response = new EIDASAuthnResponse();
	response.setPersonalAttributeList(pal);

	try {
	    getEngine().generateEIDASAuthnResponse(authenRequest, response,
		    ipAddress, isHashing);
	    fail(ERROR_TXT);
	} catch (EIDASSAMLEngineException e) {
	    authenRequest.setIssuer(issuer);
	    LOG.error("Error");
	}
    }

    /**
     * Test generate authentication response assertion consumer null.
     */
    @Test
    public final void testResponseMandatoryAssertionConsumerServiceURL() {
	final String asserConsumerUrl = authenRequest
		.getAssertionConsumerServiceURL();
	authenRequest.setAssertionConsumerServiceURL(null);

	final EIDASAuthnResponse response = new EIDASAuthnResponse();
	response.setPersonalAttributeList(pal);
	try {
	    getEngine().generateEIDASAuthnResponse(authenRequest, response,
		    ipAddress, isHashing);
	    fail("generateAuthnResponse(...) should've thrown an EIDASSAMLEngineException!");
	} catch (EIDASSAMLEngineException e) {
	    authenRequest.setAssertionConsumerServiceURL(asserConsumerUrl);
	    LOG.error("Error");
	}
    }

    /**
     * Test generate authentication response IP address null.
     */
    @Test
    public final void testResponseValidationIP() {
	final EIDASAuthnResponse response = new EIDASAuthnResponse();
	response.setPersonalAttributeList(pal);

	try {
	    getEngine().generateEIDASAuthnResponse(authenRequest, response, null,
		    isHashing);
	    fail("generateAuthnResponse(...) should've thrown an EIDASSAMLEngineException!");
	} catch (EIDASSAMLEngineException e) {
	    LOG.error("Error");
	}
    }

    /**
     * Test generate authentication response with personal attribute list null.
     */
    @Test
    public final void testResponseMandatoryPersonalAttributeList() {
	final EIDASAuthnResponse response = new EIDASAuthnResponse();
	response.setPersonalAttributeList(null);
	
	
	try {
	    getEngine().generateEIDASAuthnResponse(authenRequest, response,
		    ipAddress, isHashing);
	    fail("generateAuthnResponse(...) should've thrown an EIDASSAMLEngineException!");
	} catch (EIDASSAMLEngineException e) {
	    LOG.error("Error");
	}
    }
    
    /**
     * Test validate authentication response token null.
     */
    @Test
    public final void testResponseInvalidParametersToken() {
	try {
	    getEngine().validateEIDASAuthnResponse(null, ipAddress, 0);
	    fail(ERROR_TXT);
	} catch (EIDASSAMLEngineException e) {
	    LOG.error("Error");
	}
    }

    /**
     * Test validate authentication response IP null.
     */
    @Test
    public final void testResponseInvalidParametersIP() {
	final EIDASAuthnResponse response = new EIDASAuthnResponse();
	response.setPersonalAttributeList(pal);
	try {
	    authResponse = getEngine().generateEIDASAuthnResponse(authenRequest,
		    response, ipAddress, isNotHashing).getTokenSaml();
	    // In Conf1 ipValidate is false
	    getEngine().validateEIDASAuthnResponse(authResponse, null, 0);
	} catch (EIDASSAMLEngineException e) {
	    LOG.error("Error");
	}
    }
    
    
    /**
     * Test validate authentication response parameter name wrong.
     */
    @Test
    public final void testResponseInvalidParametersAttr() {
	final EIDASAuthnResponse response = new EIDASAuthnResponse();
	final IPersonalAttributeList wrongList = new PersonalAttributeList();

	final PersonalAttribute worngAttr = new PersonalAttribute();
	worngAttr.setName("AttrWrong");
	wrongList.add(worngAttr);
	
	
	response.setPersonalAttributeList(wrongList);
	try {
	    authResponse = getEngine().generateEIDASAuthnResponse(authenRequest,
		    response, ipAddress, isNotHashing).getTokenSaml();
	    // In Conf1 ipValidate is false
	    getEngine().validateEIDASAuthnResponse(authResponse, null, 0);
	} catch (EIDASSAMLEngineException e) {
	    LOG.error("Error");
	}
    }
    
    
    /**
     * Test validate authentication response set null value into attribute.
     */
    @Test
    public final void testResponseInvalidParametersAttrSimpleValue() {
	final EIDASAuthnResponse response = new EIDASAuthnResponse();
	final IPersonalAttributeList wrongList = new PersonalAttributeList();

	final PersonalAttribute worngAttr = new PersonalAttribute();
	worngAttr.setName("isAgeOver");
	worngAttr.setValue(null);
	wrongList.add(worngAttr);
	
	response.setPersonalAttributeList(wrongList);
	try {
	    authResponse = getEngine().generateEIDASAuthnResponse(authenRequest,
		    response, ipAddress, isNotHashing).getTokenSaml();
	    // In Conf1 ipValidate is false
	    getEngine().validateEIDASAuthnResponse(authResponse, null, 0);
	} catch (EIDASSAMLEngineException e) {
	    LOG.error("Error");
	}
    }
    
    
    /**
     * Test validate authentication response set null value into attribute.
     */
    @Test
    public final void testResponseInvalidParametersAttrNoValue() {
	final EIDASAuthnResponse response = new EIDASAuthnResponse();
	final IPersonalAttributeList wrongList = new PersonalAttributeList();

	final PersonalAttribute worngAttr = new PersonalAttribute();
	worngAttr.setName("isAgeOver");
	wrongList.add(worngAttr);
	
	response.setPersonalAttributeList(wrongList);
	try {
	    authResponse = getEngine().generateEIDASAuthnResponse(authenRequest,
		    response, ipAddress, isNotHashing).getTokenSaml();
	    // In Conf1 ipValidate is false
	    getEngine().validateEIDASAuthnResponse(authResponse, null, 0);
	} catch (EIDASSAMLEngineException e) {
	    LOG.error("Error");
	}
    }
    
    
    /**
     * Test validate authentication response set null value into attribute.
     */
    @Test
    public final void testResponseInvalidParametersAttrNoName() {
	final EIDASAuthnResponse response = new EIDASAuthnResponse();
	final IPersonalAttributeList wrongList = new PersonalAttributeList();

	final PersonalAttribute worngAttr = new PersonalAttribute();	
	wrongList.add(worngAttr);
	
	response.setPersonalAttributeList(wrongList);
	try {
	    authResponse = getEngine().generateEIDASAuthnResponse(authenRequest,
		    response, ipAddress, isNotHashing).getTokenSaml();
	    // In Conf1 ipValidate is false
	    getEngine().validateEIDASAuthnResponse(authResponse, null, 0);
	} catch (EIDASSAMLEngineException e) {
	    LOG.error("Error");
	}
    }
    
    
    /**
     * Test validate authentication response set null complex value into attribute.
     */
    @Test
    public final void testResponseInvalidParametersAttrComplexValue() {
	final EIDASAuthnResponse response = new EIDASAuthnResponse();
	final IPersonalAttributeList wrongList = new PersonalAttributeList();

	final PersonalAttribute worngAttr = new PersonalAttribute();
	worngAttr.setName("isAgeOver");
	worngAttr.setComplexValue(null);
	wrongList.add(worngAttr);
	
	response.setPersonalAttributeList(wrongList);
	try {
	    authResponse = getEngine().generateEIDASAuthnResponse(authenRequest,
		    response, ipAddress, isNotHashing).getTokenSaml();
	    // In Conf1 ipValidate is false
	    getEngine().validateEIDASAuthnResponse(authResponse, null, 0);
	} catch (EIDASSAMLEngineException e) {
	    LOG.error("Error");
	}
    }
	
    
    

    /**
     * Test validate authentication response IP distinct and disabled validation
     * IP.
     */
    @Test
    public final void testResponseInvalidParametersIPDistinct() {
	try {
	    // ipAddress origin "111.222.333.444"
	    // ipAddrValidation = false
	    // Subject Confirmation Bearer.

	    getEngine().validateEIDASAuthnResponse(authResponse, "127.0.0.1", 0);
	} catch (EIDASSAMLEngineException e) {
	    LOG.error("Error");
	    fail("validateAuthenticationResponse(...) should've thrown an EIDASSAMLEngineException!");
	}
    }

    /**
     * Test response invalid parameters invalid token.
     */
    @Test
    public final void testResponseInvalidParametersTokenMsg() {
	try {
	    // ipAddress origin "111.222.333.444"
	    // Subject Confirmation Bearer.
	    getEngine().validateEIDASAuthnResponse("errorMessage".getBytes(),
		    ipAddress, 0);
	    fail("validateAuthenticationResponse(...) should've thrown an EIDASSAMLEngineException!");
	} catch (EIDASSAMLEngineException e) {
	    LOG.error("Error");
	}
    }

    /**
     * Test validate authentication response is fail.
     * 
     * @throws EIDASSAMLEngineException the EIDASSAML engine exception
     */
    @Test
    public final void testValidateAuthenticationResponseIsFail()
	    throws EIDASSAMLEngineException {
		testGenerateAuthnResponse();//prepare valid authnResponse
		authnResponse = getEngine().validateEIDASAuthnResponse(authResponse,
			ipAddress, 0);
		assertFalse("Generate incorrect response: ", authnResponse.isFail());
    }

    /**
     * Test validate authentication response destination.
     * 
     * @throws EIDASSAMLEngineException the EIDASSAML engine exception
     */
    @Test
    public final void testValidateAuthenticationResponseDestination()
	    throws EIDASSAMLEngineException {
	authnResponse = getEngine().validateEIDASAuthnResponse(authResponse,
		ipAddress, 0);

	assertEquals("Destination incorrect: ",
		authnResponse.getInResponseTo(), authenRequest.getSamlId());
    }

    /**
     * Test validate authentication response values.
     * 
     * @throws EIDASSAMLEngineException the EIDASSAML engine exception
     */
    public final void testValidateAuthenticationResponseValuesComplex()
	    throws EIDASSAMLEngineException {
	authnResponse = getEngine().validateEIDASAuthnResponse(authResponse,
		ipAddress, 0);
	
	assertEquals("Country incorrect:", authnResponse.getCountry(), "EN");
	
	final Iterator<PersonalAttribute> iterator = authnResponse
		.getPersonalAttributeList().iterator();

	while (iterator.hasNext()) {
	    final PersonalAttribute attribute = iterator.next();
	    if (attribute.getName().equalsIgnoreCase(
		    "canonicalResidenceAddress")) {
		assertEquals("State incorrect: ", state, attribute
			.getComplexValue().get("state"));
		assertEquals("Municipality Code incorrect: ", municipalityCode,
			attribute.getComplexValue().get("municipalityCode"));
		assertEquals("Town incorrect: ", town, attribute
			.getComplexValue().get("town"));
		assertEquals("Postal code incorrect: ", postalCode, attribute
			.getComplexValue().get("postalCode"));
		assertEquals("Street name incorrect: ", streetName, attribute
			.getComplexValue().get("streetName"));
		assertEquals("Street number incorrect: ", streetNumber,
			attribute.getComplexValue().get("streetNumber"));
		assertEquals("Apartament number incorrect: ", apartamentNumber,
			attribute.getComplexValue().get("apartamentNumber"));
	    }
	}
    }

    /**
     * Test generate authenticate response fail in response to it's null.
     * @throws EIDASSAMLEngineException 
     * 
     * @throws EIDASSAMLEngineException the EIDASSAML engine exception
     */
    @Test //( expected=EIDASSAMLEngineException.class)
    public final void testGenerateAuthnResponseFailInResponseToNull() throws EIDASSAMLEngineException {
	final String identifier = authenRequest.getSamlId();
	authenRequest.setSamlId(null);

	final EIDASAuthnResponse response = new EIDASAuthnResponse();
	response.setStatusCode(EIDASStatusCode.REQUESTER_URI.toString());
	response.setSubStatusCode(EIDASSubStatusCode.AUTHN_FAILED_URI.toString());
	response.setMessage("");

	try {
	    authResponse = getEngine().generateEIDASAuthnResponseFail(authenRequest,
		    response, ipAddress, isNotHashing).getTokenSaml();
	    fail(ERROR_TXT);
	} catch (EIDASSAMLEngineException e) {
	    authenRequest.setSamlId(identifier);
	    LOG.error("Error");
	    //throw new EIDASSAMLEngineException(e);
	}
    }

    /**
     * Test generate authenticate response fail assertion consumer URL err1.
     * 
     * @throws EIDASSAMLEngineException the EIDASSAML engine exception
     */
    @Test
    public final void testGenerateAuthnResponseFailAssertionConsumerUrlNull()
	    throws EIDASSAMLEngineException {

	final String assertConsumerUrl = authenRequest
		.getAssertionConsumerServiceURL();
	authenRequest.setAssertionConsumerServiceURL(null);

	final EIDASAuthnResponse response = new EIDASAuthnResponse();
	response.setStatusCode(EIDASStatusCode.REQUESTER_URI.toString());
	response.setSubStatusCode(EIDASSubStatusCode.AUTHN_FAILED_URI.toString());
	response.setMessage("");

	try {
	    authResponse = getEngine().generateEIDASAuthnResponseFail(authenRequest,
		    response, ipAddress, isNotHashing).getTokenSaml();
	    fail("generateAuthnResponseFail(...) should've thrown an EIDASSAMLEngineException!");
	} catch (EIDASSAMLEngineException e) {
	    authenRequest.setAssertionConsumerServiceURL(assertConsumerUrl);
	    LOG.error("Error");
	}
    }

    /**
     * Test generate authentication response fail code error err1.
     * 
     * @throws EIDASSAMLEngineException the EIDASSAML engine exception
     */
    @Test
    public final void testGenerateAuthnResponseFailCodeErrorNull()
	    throws EIDASSAMLEngineException {
	final EIDASAuthnResponse response = new EIDASAuthnResponse();
	response.setStatusCode(null);
	response.setSubStatusCode(EIDASSubStatusCode.AUTHN_FAILED_URI.toString());
	response.setMessage("");

	try {
	    authResponse = getEngine().generateEIDASAuthnResponseFail(authenRequest,
		    response, ipAddress, isNotHashing).getTokenSaml();
	    fail("generateAuthnResponseFail(...) should've thrown an EIDASSAMLEngineException!");
	} catch (EIDASSAMLEngineException e) {
	    LOG.error("Error");
	}
    }
    
    
    
    
    /**
     * Test generate authentication request without errors.
     * 
     * @throws EIDASSAMLEngineException the EIDASSAML engine exception
     */
    @Test
    public final void testValidateAuthnResponse() throws EIDASSAMLEngineException {
	
	IPersonalAttributeList palist = new PersonalAttributeList();

	PersonalAttribute isAgeOver = new PersonalAttribute();
	isAgeOver.setName("isAgeOver");
	isAgeOver.setIsRequired(true);
	ArrayList<String> ages = new ArrayList<String>();
	ages.add("16");
	ages.add("18");
	isAgeOver.setValue(ages);
	isAgeOver.setStatus(EIDASStatusCode.STATUS_AVAILABLE.toString());
	palist.add(isAgeOver);

	PersonalAttribute dateOfBirth = new PersonalAttribute();
	dateOfBirth.setName("dateOfBirth");
	dateOfBirth.setIsRequired(false);
	final ArrayList<String> date = new ArrayList<String>();
	date.add("16/12/2008");
	dateOfBirth.setValue(date);
	dateOfBirth.setStatus(EIDASStatusCode.STATUS_AVAILABLE.toString());
	palist.add(dateOfBirth);

	
	PersonalAttribute eIDNumber = new PersonalAttribute();
	eIDNumber.setName("eIdentifier");
	eIDNumber.setIsRequired(true);

	final ArrayList<String> idNumber = new ArrayList<String>();
	idNumber.add("123456789PÑ");
	
	final HashMap<String, String> complex = new HashMap<String, String>();
	complex.put("one", "two");

	//eIDNumber.setValue(null);
	//eIDNumber.setValue(idNumber);
	//eIDNumber.setComplexValue(complex);
	
	eIDNumber.setStatus(EIDASStatusCode.STATUS_NOT_AVAILABLE.toString());
	palist.add(eIDNumber);

	PersonalAttribute canRessAddress = new PersonalAttribute();	
	canRessAddress.setName("canonicalResidenceAddress");
	canRessAddress.setIsRequired(true);
	canRessAddress.setStatus(EIDASStatusCode.STATUS_AVAILABLE.toString());
	final HashMap<String, String> address = new HashMap<String, String>();

	address.put("state", state);
	address.put("municipalityCode", municipalityCode);
	address.put("town", town);
	address.put("postalCode", postalCode);
	address.put("streetName", streetName);
	address.put("streetNumber", streetNumber);
	address.put("apartamentNumber", apartamentNumber);

	canRessAddress.setComplexValue(address);
	palist.add(canRessAddress);

	
	final EIDASAuthnResponse response = new EIDASAuthnResponse();

	response.setPersonalAttributeList(palist);

	final EIDASAuthnResponse eidasResponse = getEngine()
		.generateEIDASAuthnResponse(authenRequest, response, ipAddress,
			isNotHashing);

	authResponse = eidasResponse.getTokenSaml();
	LOG.info("Request id: " + authenRequest.getSamlId());
	
	LOG.info("RESPONSE: " + SSETestUtils.encodeSAMLToken(authResponse));
	
	
	authnResponse = getEngine().validateEIDASAuthnResponse(authResponse,
		ipAddress, 0);
	
	LOG.info("RESPONSE ID: " + authnResponse.getSamlId());
	LOG.info("RESPONSE IN_RESPONSE_TO: " + authnResponse.getInResponseTo());
	LOG.info("RESPONSE COUNTRY: " + authnResponse.getCountry());
	
    }
    
    
   

	
    /**
     * Test validate authentication response fail is fail.
     * 
     * @throws EIDASSAMLEngineException the EIDASSAML engine exception
     */
    @Test
    public final void testValidateAuthenticationResponseFailIsFail()
	    throws EIDASSAMLEngineException {

	final EIDASAuthnResponse response = new EIDASAuthnResponse();
	response.setStatusCode(EIDASStatusCode.REQUESTER_URI.toString());
	response.setSubStatusCode(EIDASSubStatusCode.AUTHN_FAILED_URI.toString());
	response.setMessage("message");

	authResponse = getEngine().generateEIDASAuthnResponseFail(authenRequest,
		response, ipAddress, isNotHashing).getTokenSaml();
	
	LOG.error("ERROR_FAIL: " + EIDASUtil.encodeSAMLToken(authResponse));

	authnResponse = getEngine().validateEIDASAuthnResponse(authResponse,
		ipAddress, 0);

	LOG.info("COUNTRY: " + authnResponse.getCountry());
	assertTrue("Generate incorrect response: ", authnResponse.isFail());
    }  
    
	/**
	 * Test generate/validate response with signedDoc
	 * 
	 * @throws EIDASSAMLEngineException
	 *             the EIDASSAML engine exception
	 */
	@Test
	public final void testGenerateAuthenResponseWithSignedDoc()
			throws EIDASSAMLEngineException {

		String signedDocResponse = "<dss:SignResponse xmlns:dss=\"urn:oasis:names:tc:dss:1.0:core:schema\" RequestID=\"123456\"> <dss:Result> <dss:ResultMajor>urn:oasis:names:tc:dss:1.0:resultmajor:Success</dss:ResultMajor> </dss:Result> <dss:SignatureObject> <dss:Base64Signature Type=\"urn:ietf:rfc:3275\">PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48ZHM6U2lnbmF0dXJlIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIiBJZD0iU2lnbmF0dXJlLThlYWJkMGE1LTY2MGQtNGFmZC05OTA1LTBhYmM3NTUzZDE5Mi1TaWduYXR1cmUiPjxkczpTaWduZWRJbmZvPjxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvVFIvMjAwMS9SRUMteG1sLWMxNG4tMjAwMTAzMTUiLz48ZHM6U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3JzYS1zaGExIi8+PGRzOlJlZmVyZW5jZSBJZD0iUmVmZXJlbmNlLWJhYmE0ZDFhLWExN2UtNDJjNi05N2QyLWJlZWUxMzUwOTUwMyIgVHlwZT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI09iamVjdCIgVVJJPSIjT2JqZWN0LTk4NzMzY2RlLThiY2MtNDhhMC05Yjc3LTBlOTk5N2JkZDA1OCI+PGRzOlRyYW5zZm9ybXM+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNiYXNlNjQiLz48L2RzOlRyYW5zZm9ybXM+PGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNzaGExIi8+PGRzOkRpZ2VzdFZhbHVlPkNrMVZxTmQ0NVFJdnEzQVpkOFhZUUx2RWh0QT08L2RzOkRpZ2VzdFZhbHVlPjwvZHM6UmVmZXJlbmNlPjxkczpSZWZlcmVuY2UgVHlwZT0iaHR0cDovL3VyaS5ldHNpLm9yZy8wMTkwMyNTaWduZWRQcm9wZXJ0aWVzIiBVUkk9IiNTaWduYXR1cmUtOGVhYmQwYTUtNjYwZC00YWZkLTk5MDUtMGFiYzc1NTNkMTkyLVNpZ25lZFByb3BlcnRpZXMiPjxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjc2hhMSIvPjxkczpEaWdlc3RWYWx1ZT5BNVk5MW40cXBMZ3l0VFc3ZnhqWENVZVJ2NTQ9PC9kczpEaWdlc3RWYWx1ZT48L2RzOlJlZmVyZW5jZT48ZHM6UmVmZXJlbmNlIFVSST0iI1NpZ25hdHVyZS04ZWFiZDBhNS02NjBkLTRhZmQtOTkwNS0wYWJjNzU1M2QxOTItS2V5SW5mbyI+PGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNzaGExIi8+PGRzOkRpZ2VzdFZhbHVlPlZQWDRuS0Z5UzZyRitGNmNSUjBQck5aZHc2Zz08L2RzOkRpZ2VzdFZhbHVlPjwvZHM6UmVmZXJlbmNlPjwvZHM6U2lnbmVkSW5mbz48ZHM6U2lnbmF0dXJlVmFsdWUgSWQ9IlNpZ25hdHVyZS04ZWFiZDBhNS02NjBkLTRhZmQtOTkwNS0wYWJjNzU1M2QxOTItU2lnbmF0dXJlVmFsdWUiPkxiS04vL0M3WGt5eFR0WVRpQ1VScjhuWnp4QW1zdGNNZDBDZ0VBQ3JLMWR5Z1JIcUdjSzR4dHMrV0NVOFB5RXFXclJJVFl6SXV3LzcNClY0Wno5VFQ2MHA0S1RNZXd1UUw2NHNrRVN4MllnMkVkaWtTTyt0S3hXa2hyYVVzbVZiR2JQbW1jbUR2OTd0SER3ODg3NDdlRnE1RjUNCnYrYVZTeUF6MDNpVUttdVNlSDg9PC9kczpTaWduYXR1cmVWYWx1ZT48ZHM6S2V5SW5mbyBJZD0iU2lnbmF0dXJlLThlYWJkMGE1LTY2MGQtNGFmZC05OTA1LTBhYmM3NTUzZDE5Mi1LZXlJbmZvIj48ZHM6S2V5VmFsdWU+PGRzOlJTQUtleVZhbHVlPjxkczpNb2R1bHVzPnd1Y21qOXRJV3J2d2JTVFVEZndLbCtKdERNTUVSMGNMZDZEa0JTcjc5MHQrckdOakVTcVlqUndFSWVCbktvUUhQeDVIb1JlRjg4L3QNCnFZOStDaEVYcExITHM5cDVhWDdTREp1YnBRTWZwMXRERlgzNHl3Z3hTUXZjZWVKUVdCWGppZXVJbWZDMjFzNGJPY2dKYlYxaGJpZ1MNCnpPS1RRS3IxVHpkR1IrdVJ5MDA9PC9kczpNb2R1bHVzPjxkczpFeHBvbmVudD5BUUFCPC9kczpFeHBvbmVudD48L2RzOlJTQUtleVZhbHVlPjwvZHM6S2V5VmFsdWU+PGRzOlg1MDlEYXRhPjxkczpYNTA5Q2VydGlmaWNhdGU+TUlJSW1UQ0NCNEdnQXdJQkFnSURBWFVVTUEwR0NTcUdTSWIzRFFFQkJRVUFNSUlCT3pFTE1Ba0dBMVVFQmhNQ1JWTXhPekE1QmdOVg0KQkFvVE1rRm5aVzVqYVdFZ1EyRjBZV3hoYm1FZ1pHVWdRMlZ5ZEdsbWFXTmhZMmx2SUNoT1NVWWdVUzB3T0RBeE1UYzJMVWtwTVRRdw0KTWdZRFZRUUhFeXRRWVhOellYUm5aU0JrWlNCc1lTQkRiMjVqWlhCamFXOGdNVEVnTURnd01EZ2dRbUZ5WTJWc2IyNWhNUzR3TEFZRA0KVlFRTEV5VlRaWEoyWldseklGQjFZbXhwWTNNZ1pHVWdRMlZ5ZEdsbWFXTmhZMmx2SUVWRFZpMHlNVFV3TXdZRFZRUUxFeXhXWldkbA0KZFNCb2RIUndjem92TDNkM2R5NWpZWFJqWlhKMExtNWxkQzkyWlhKRFNVTXRNaUFvWXlrd016RTFNRE1HQTFVRUN4TXNSVzUwYVhSaA0KZENCd2RXSnNhV05oSUdSbElHTmxjblJwWm1sallXTnBieUJrWlNCamFYVjBZV1JoYm5NeEd6QVpCZ05WQkFNVEVsQlNSVkJTVDBSVg0KUTBOSlR5QkpSRU5oZERBZUZ3MHhNREF5TVRFeE9ESXlNRFJhRncweE5EQXlNVEF4T0RJeU1EUmFNSUd3TVFzd0NRWURWUVFHRXdKRg0KVXpFMU1ETUdBMVVFQ3hNc1ZtVm5aWFVnYUhSMGNITTZMeTkzZDNjdVkyRjBZMlZ5ZEM1dVpYUXZkbVZ5U1VSRFlYUWdLR01wTURNeA0KRmpBVUJnTlZCQVFURFVKRlVreEJUa2RCSUZOUFZFOHhGekFWQmdOVkJDb1REazFCVWtsQklFVk9SMUpCUTBsQk1SSXdFQVlEVlFRRg0KRXdreE1EQXdNRGswTkZNeEpUQWpCZ05WQkFNVEhFMUJVa2xCSUVWT1IxSkJRMGxCSUVKRlVreEJUa2RCSUZOUFZFOHdnWjh3RFFZSg0KS29aSWh2Y05BUUVCQlFBRGdZMEFNSUdKQW9HQkFNTG5Kby9iU0ZxNzhHMGsxQTM4Q3BmaWJRekRCRWRIQzNlZzVBVXErL2RMZnF4ag0KWXhFcW1JMGNCQ0hnWnlxRUJ6OGVSNkVYaGZQUDdhbVBmZ29SRjZTeHk3UGFlV2wrMGd5Ym02VURINmRiUXhWOStNc0lNVWtMM0huaQ0KVUZnVjQ0bnJpSm53dHRiT0d6bklDVzFkWVc0b0VzemlrMENxOVU4M1JrZnJrY3ROQWdNQkFBR2pnZ1N3TUlJRXJEQU1CZ05WSFJNQg0KQWY4RUFqQUFNQTRHQTFVZER3RUIvd1FFQXdJRm9EQ0J6QVlEVlIwUkJJSEVNSUhCZ1E5aWMyOTBiMEJuYldGcGJDNWpiMjJrZ1lVdw0KZ1lJeEN6QUpCZ05WQkFZVEFrVlRNU3N3S1FZRFZRUUtGQ0pCWjhPb2JtTnBZU0JEWVhSaGJHRnVZU0JrWlNCRFpYSjBhV1pwWTJGag0KYWNPek1RNHdEQVlEVlFRTEV3VkpSRU5CVkRFUE1BMEdBMVVFQlJNR01ERTNOVEUwTVNVd0l3WURWUVFERXh4TlFWSkpRU0JGVGtkUw0KUVVOSlFTQkNSVkpNUVU1SFFTQlRUMVJQb0JBR0Npc0dBUVFCOVhnQkFRR2dBZ3dBb0JRR0RsWUVBQUVEQmdFRUFmVjRBUUVDb0FJTQ0KQURBZkJnTlZIUklFR0RBV2dSUmxZMTlwWkdOaGRFQmpZWFJqWlhKMExtNWxkREFkQmdOVkhRNEVGZ1FVQUZYanVOc2tCMk1seXZVQg0KaDdwOFRKMHVKMHd3Z2dGSUJnTlZIU01FZ2dFL01JSUJPNEFVUkt2Y2tVaE4xNGg0Q24vZ2RPRG42NzIzS1Z5aGdnRVBwSUlCQ3pDQw0KQVFjeEN6QUpCZ05WQkFZVEFrVlRNVHN3T1FZRFZRUUtFekpCWjJWdVkybGhJRU5oZEdGc1lXNWhJR1JsSUVObGNuUnBabWxqWVdOcA0KYnlBb1RrbEdJRkV0TURnd01URTNOaTFKS1RFb01DWUdBMVVFQ3hNZlUyVnlkbVZwY3lCUWRXSnNhV056SUdSbElFTmxjblJwWm1sag0KWVdOcGJ6RThNRG9HQTFVRUN4TXpWbVZuWlhVZ2FIUjBjSE02THk5M2QzY3VZMkYwWTJWeWRDNXVaWFF2ZG1WeWNISmxjSEp2WkhWag0KWTJsdklDaGpLVEF6TVRVd013WURWUVFMRXl4S1pYSmhjbkYxYVdFZ1JXNTBhWFJoZEhNZ1pHVWdRMlZ5ZEdsbWFXTmhZMmx2SUVOaA0KZEdGc1lXNWxjekVjTUJvR0ExVUVBeE1UVUZKRlVGSlBSRlZEUTBsUElFVkRMVUZEUTRJUWR3S1R0TTFFRVU5RkVQWFVZSGdnaERBZA0KQmdOVkhTVUVGakFVQmdnckJnRUZCUWNEQWdZSUt3WUJCUVVIQXdRd0VRWUpZSVpJQVliNFFnRUJCQVFEQWdXZ01EUUdDQ3NHQVFVRg0KQndFQkJDZ3dKakFrQmdnckJnRUZCUWN3QVlZWWFIUjBjSE02THk5dlkzTndMbU5oZEdObGNuUXVibVYwTUJnR0NDc0dBUVVGQndFRA0KQkF3d0NqQUlCZ1lFQUk1R0FRRXdnWVlHQTFVZEh3Ui9NSDB3UEtBNm9EaUdObWgwZEhBNkx5OWxjSE5qWkM1allYUmpaWEowTG01bA0KZEM5amNtd3ZjSEpsY0hKdlpIVmpZMmx2WDJWakxXbGtZMkYwTG1OeWJEQTlvRHVnT1lZM2FIUjBjRG92TDJWd2MyTmtNaTVqWVhSag0KWlhKMExtNWxkQzlqY213dmNISmxjSEp2WkhWalkybHZYMlZqTFdsa1kyRjBMbU55YkRDQjlnWURWUjBnQklIdU1JSHJNSUhvQmd3cg0KQmdFRUFmVjRBUU1CVmdFd2dkY3dMQVlJS3dZQkJRVUhBZ0VXSUdoMGRIQnpPaTh2ZDNkM0xtTmhkR05sY25RdWJtVjBMM1psY2tsRQ0KUTJGME1JR21CZ2dyQmdFRkJRY0NBakNCbVJxQmxrRnhkV1Z6ZENEdnY3MXpJSFZ1SUdObGNuUnBabWxqWVhRZ2NHVnljMjl1WVd3Zw0KU1VSRFFWUXNJSEpsWTI5dVpXZDFkQ0JrSjJsa1pXNTBhV1pwWTJGajc3KzlMQ0J6YVdkdVlYUjFjbUVnYVNCNGFXWnlZWFFnWkdVZw0KWTJ4aGMzTmxJRElnYVc1a2FYWnBaSFZoYkM0Z1ZtVm5aWFVnYUhSMGNITTZMeTkzZDNjdVkyRjBZMlZ5ZEM1dVpYUXZkbVZ5UkVOaA0KZERBdEJnTlZIUWtFSmpBa01CQUdDQ3NHQVFVRkJ3a0VNUVFUQWtWVE1CQUdDQ3NHQVFVRkJ3a0ZNUVFUQWtWVE1BMEdDU3FHU0liMw0KRFFFQkJRVUFBNElCQVFDcTc3ODBSR1FNTEIxZ2tkTk1mTFhuZ3FNb1JIR0taYnZ6a3JxSUFtVDhXQWQxRThyQXBoUjkveExKVXRwNQ0KbGJnMmZScjVibDJqOE9WREJLMlltRzQxaDhBRG40U1RJL0FwZU5JTlNmalpzNk5Sc25XekZ5ZlhYbVBDSFlGQi9YV3p5aW1DRXhndg0KdnR1SCszUUF3Y3dobjUwUExFdWh3NUM1dmxYN0x5NUs2ckxMTUZOVVVNYldWeTFoWmVsSy9DQlRjQWpJTzM4TlkrdllSQU1LU2Y0TQ0KL2daUXo0cUJlRlZKYTUyUjdOY0FxQ2ZyZkxmYVhwYkRTZzk4eG9CZU5zMmluR3p4OFVTZ0VyTFpqS0pzZG4vS2pURDlnUy9zVGRRNg0KUTdpZHFsZDJMRlZsTzIvYjk0Wk5aQmNTLzc4RU9EWGdkV2ZreVBDN1J3OHJlOW5JMy9qVDwvZHM6WDUwOUNlcnRpZmljYXRlPjwvZHM6WDUwOURhdGE+PC9kczpLZXlJbmZvPjxkczpPYmplY3QgRW5jb2Rpbmc9ImJhc2U2NCIgSWQ9Ik9iamVjdC05ODczM2NkZS04YmNjLTQ4YTAtOWI3Ny0wZTk5OTdiZGQwNTgiIE1pbWVUeXBlPSJhcHBsaWNhdGlvbi9vY3RldC1zdHJlYW0iPlNHVnNiRzhnVjI5eWJHUT08L2RzOk9iamVjdD48ZHM6T2JqZWN0Pjx4YWRlczpRdWFsaWZ5aW5nUHJvcGVydGllcyB4bWxuczp4YWRlcz0iaHR0cDovL3VyaS5ldHNpLm9yZy8wMTkwMy92MS4zLjIjIiBJZD0iU2lnbmF0dXJlLThlYWJkMGE1LTY2MGQtNGFmZC05OTA1LTBhYmM3NTUzZDE5Mi1RdWFsaWZ5aW5nUHJvcGVydGllcyIgVGFyZ2V0PSIjU2lnbmF0dXJlLThlYWJkMGE1LTY2MGQtNGFmZC05OTA1LTBhYmM3NTUzZDE5Mi1TaWduYXR1cmUiPjx4YWRlczpTaWduZWRQcm9wZXJ0aWVzIElkPSJTaWduYXR1cmUtOGVhYmQwYTUtNjYwZC00YWZkLTk5MDUtMGFiYzc1NTNkMTkyLVNpZ25lZFByb3BlcnRpZXMiPjx4YWRlczpTaWduZWRTaWduYXR1cmVQcm9wZXJ0aWVzPjx4YWRlczpTaWduaW5nVGltZT4yMDExLTAzLTIxVDExOjQ0OjQyKzAxOjAwPC94YWRlczpTaWduaW5nVGltZT48eGFkZXM6U2lnbmluZ0NlcnRpZmljYXRlPjx4YWRlczpDZXJ0Pjx4YWRlczpDZXJ0RGlnZXN0PjxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjc2hhMSIvPjxkczpEaWdlc3RWYWx1ZT4zbTZ3OTlUb3lTZDlKcEJsMWdCazhEei9iYlU9PC9kczpEaWdlc3RWYWx1ZT48L3hhZGVzOkNlcnREaWdlc3Q+PHhhZGVzOklzc3VlclNlcmlhbD48ZHM6WDUwOUlzc3Vlck5hbWU+Q049UFJFUFJPRFVDQ0lPIElEQ2F0LCBPVT1FbnRpdGF0IHB1YmxpY2EgZGUgY2VydGlmaWNhY2lvIGRlIGNpdXRhZGFucywgT1U9VmVnZXUgaHR0cHM6Ly93d3cuY2F0Y2VydC5uZXQvdmVyQ0lDLTIgKGMpMDMsIE9VPVNlcnZlaXMgUHVibGljcyBkZSBDZXJ0aWZpY2FjaW8gRUNWLTIsIEw9UGFzc2F0Z2UgZGUgbGEgQ29uY2VwY2lvIDExIDA4MDA4IEJhcmNlbG9uYSwgTz1BZ2VuY2lhIENhdGFsYW5hIGRlIENlcnRpZmljYWNpbyAoTklGIFEtMDgwMTE3Ni1JKSwgQz1FUzwvZHM6WDUwOUlzc3Vlck5hbWU+PGRzOlg1MDlTZXJpYWxOdW1iZXI+OTU1MDg8L2RzOlg1MDlTZXJpYWxOdW1iZXI+PC94YWRlczpJc3N1ZXJTZXJpYWw+PC94YWRlczpDZXJ0PjwveGFkZXM6U2lnbmluZ0NlcnRpZmljYXRlPjwveGFkZXM6U2lnbmVkU2lnbmF0dXJlUHJvcGVydGllcz48eGFkZXM6U2lnbmVkRGF0YU9iamVjdFByb3BlcnRpZXM+PHhhZGVzOkRhdGFPYmplY3RGb3JtYXQgT2JqZWN0UmVmZXJlbmNlPSIjUmVmZXJlbmNlLWJhYmE0ZDFhLWExN2UtNDJjNi05N2QyLWJlZWUxMzUwOTUwMyI+PHhhZGVzOk1pbWVUeXBlPmFwcGxpY2F0aW9uL29jdGV0LXN0cmVhbTwveGFkZXM6TWltZVR5cGU+PHhhZGVzOkVuY29kaW5nPmJhc2U2NDwveGFkZXM6RW5jb2Rpbmc+PC94YWRlczpEYXRhT2JqZWN0Rm9ybWF0PjwveGFkZXM6U2lnbmVkRGF0YU9iamVjdFByb3BlcnRpZXM+PC94YWRlczpTaWduZWRQcm9wZXJ0aWVzPjwveGFkZXM6UXVhbGlmeWluZ1Byb3BlcnRpZXM+PC9kczpPYmplY3Q+PC9kczpTaWduYXR1cmU+</dss:Base64Signature> </dss:SignatureObject> </dss:SignResponse>";

		IPersonalAttributeList palist = new PersonalAttributeList();

		PersonalAttribute signedDoc = new PersonalAttribute();
		signedDoc.setName("signedDoc");
		signedDoc.setIsRequired(false);
		ArrayList<String> signed = new ArrayList<String>();
		signed.add(signedDocResponse);
		signedDoc.setValue(signed);
		palist.add(signedDoc);

		PersonalAttribute isAgeOver = new PersonalAttribute();
		isAgeOver.setName("isAgeOver");
		isAgeOver.setIsRequired(false);
		ArrayList<String> ages = new ArrayList<String>();
		ages.add("16");
		ages.add("18");
		isAgeOver.setValue(ages);
		palist.add(isAgeOver);

		authenRequest.setPersonalAttributeList(palist);

		final EIDASAuthnResponse response = new EIDASAuthnResponse();

		response.setPersonalAttributeList(palist);

		final EIDASAuthnResponse eidasResponse = getEngine()
				.generateEIDASAuthnResponse(authenRequest, response, ipAddress,
						isNotHashing);

		authResponse = eidasResponse.getTokenSaml();
		authnResponse = getEngine().validateEIDASAuthnResponse(authResponse,
				ipAddress, 0);

		assertTrue("SignedDoc response should be the same: ", authnResponse
				.getPersonalAttributeList().get("signedDoc").getValue().get(0)
				.equals(signedDocResponse));

	}

}
