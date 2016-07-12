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

package eu.stork.peps.test.simple.eidas;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

import eu.stork.peps.auth.engine.core.eidas.EidasExtensionProcessor;
import eu.stork.peps.test.simple.SSETestUtils;
import org.junit.Test;
import org.opensaml.xml.parse.BasicParserPool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.stork.peps.auth.commons.IPersonalAttributeList;
import eu.stork.peps.auth.commons.PEPSUtil;
import eu.stork.peps.auth.commons.PersonalAttribute;
import eu.stork.peps.auth.commons.PersonalAttributeList;
import eu.stork.peps.auth.commons.STORKAuthnRequest;
import eu.stork.peps.auth.commons.STORKAuthnResponse;
import eu.stork.peps.auth.commons.STORKStatusCode;
import eu.stork.peps.auth.commons.STORKSubStatusCode;
import eu.stork.peps.auth.engine.STORKSAMLEngine;
import eu.stork.peps.exceptions.STORKSAMLEngineException;

/**
 * The Class AuthRequestTest.
 */
public class EidasResponseTest {
    
    /** The engine. */
    private static STORKSAMLEngine engine = null;
	static{
		try{
			engine = STORKSAMLEngine.createSTORKSAMLEngine("CONF1");
			engine.setExtensionProcessor(new EidasExtensionProcessor());

		}catch(STORKSAMLEngineException e){
			fail("Failed to initialize SAMLEngines");
		}
	}

    /**
     * Gets the engine.
     * 
     * @return the engine
     */
    public static STORKSAMLEngine getEngine() {
        return engine;
    }

    /**
     * Sets the engine.
     * 
     * @param newEngine the new engine
     */
    public static void setEngine(final STORKSAMLEngine newEngine) {
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
    private static STORKAuthnRequest authenRequest;

    /** The authentication response. */
    private static STORKAuthnResponse authnResponse;

    /** The Constant LOG. */
    private static final Logger LOG = LoggerFactory
	    .getLogger(eu.stork.peps.test.simple.StorkResponseTest.class.getName());

    /**
     * Instantiates a new stork response test.
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
    private static final String ERROR_TXT = "generateAuthnResponse(...) should've thrown an STORKSAMLEngineException!";


    /** Parser manager used to parse XML. */
    private static BasicParserPool parser;
    
    

    static {
		parser = STORKSAMLEngine.getNewBasicSecuredParserPool();

		pal = new PersonalAttributeList();

		PersonalAttribute dateOfBirth = new PersonalAttribute();
		dateOfBirth.setName("DateOfBirth");
		dateOfBirth.setIsRequired(false);
		pal.add(dateOfBirth);

		PersonalAttribute eIDNumber = new PersonalAttribute();
		eIDNumber.setName("PersonIdentifier");
		eIDNumber.setIsRequired(true);
		pal.add(eIDNumber);

		PersonalAttribute givenName = new PersonalAttribute();
		givenName.setName("FirstName");
		givenName.setIsRequired(true);
		pal.add(givenName);

		PersonalAttribute canRessAddress = new PersonalAttribute();
		canRessAddress.setName("CurrentAddress");
		canRessAddress.setIsRequired(true);
		pal.add(canRessAddress);



		destination = "http://C-PEPS.gov.xx/PEPS/ColleagueRequest";
		assertConsumerUrl = "http://S-PEPS.gov.xx/PEPS/ColleagueResponse";
		spName = "University Oxford";

		spName = "University of Oxford";
		spSector = "EDU001";
		spInstitution = "OXF001";
		spApplication = "APP001";
		spCountry = "EN";

		spId = "EDU001-APP001-APP001";

		final STORKAuthnRequest request = new STORKAuthnRequest();
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
		request.setSPType("public");

	try {
	    authRequest = getEngine().generateSTORKAuthnRequest(request)
		    .getTokenSaml();
	    	    
	    authenRequest = getEngine().validateSTORKAuthnRequest(authRequest);
	    
	} catch (STORKSAMLEngineException e) {
	    fail("Error create STORKAuthnRequest");
	}

	ipAddress = "111.222.333.444";

	pal = new PersonalAttributeList();


	dateOfBirth = new PersonalAttribute();
	dateOfBirth.setName("DateOfBirth");
	dateOfBirth.setIsRequired(false);
	final ArrayList<String> date = new ArrayList<String>();
	date.add("2008-12-16");
	dateOfBirth.setValue(date);
	dateOfBirth.setStatus(STORKStatusCode.STATUS_AVAILABLE.toString());
	pal.add(dateOfBirth);

	eIDNumber = new PersonalAttribute();
	eIDNumber.setName("PersonIdentifier");
	eIDNumber.setIsRequired(true);
	final ArrayList<String> idNumber = new ArrayList<String>();
	idNumber.add("123456789PÑ");
	eIDNumber.setValue(idNumber);
	eIDNumber.setStatus(STORKStatusCode.STATUS_AVAILABLE.toString());
	pal.add(eIDNumber);

		PersonalAttribute currentFamilyName = new PersonalAttribute();
		currentFamilyName.setName("FamilyName");
		currentFamilyName.setIsRequired(true);
		final ArrayList<String> currentFamilyNamevalues = new ArrayList<String>();
		currentFamilyNamevalues.add("\u03A9\u03BD\u03AC\u03C3\u03B7\u03C2");
		currentFamilyName.setValue(currentFamilyNamevalues);
		currentFamilyName.setStatus(STORKStatusCode.STATUS_AVAILABLE.toString());
		pal.add(currentFamilyName);

		canRessAddress = new PersonalAttribute();
	canRessAddress.setName("CurrentAddress");
	canRessAddress.setIsRequired(true);
	canRessAddress.setStatus(STORKStatusCode.STATUS_AVAILABLE.toString());
//	final HashMap<String, String> address = new HashMap<String, String>();
//
//	address.put("state", state);
//	address.put("municipalityCode", municipalityCode);
//	address.put("town", town);
//	address.put("postalCode", postalCode);
//	address.put("streetName", streetName);
//	address.put("streetNumber", streetNumber);
//	address.put("apartamentNumber", apartamentNumber);

		final ArrayList<String> addressValue = new ArrayList<String>();
		addressValue.add("address value");
	canRessAddress.setValue(addressValue);
	pal.add(canRessAddress);
    }

    /**
     * Test generate authentication request without errors.
     * 
     * @throws STORKSAMLEngineException the STORKSAML engine exception
     */
    @Test
    public final void testGenerateAuthnResponse() throws STORKSAMLEngineException {

	final STORKAuthnResponse response = new STORKAuthnResponse();
	response.setPersonalAttributeList(pal);

	final STORKAuthnResponse storkResponse = getEngine()
		.generateSTORKAuthnResponse(authenRequest, response, ipAddress,
			isNotHashing);

	authResponse = storkResponse.getTokenSaml();
	String result = new String(authResponse);
	LOG.info("RESPONSE: " + SSETestUtils.encodeSAMLToken(authResponse));
	LOG.info("RESPONSE as string: " + result);
	
    }

    /**
     * Test validation id parameter mandatory.
     */
    @Test
    public final void testResponseMandatoryId() {
	final String identifier = authenRequest.getSamlId();
	authenRequest.setSamlId(null);

	final STORKAuthnResponse response = new STORKAuthnResponse();
	response.setPersonalAttributeList(pal);

	try {
	    getEngine().generateSTORKAuthnResponse(authenRequest, response,
		    ipAddress, isHashing);
	    fail(ERROR_TXT);
	} catch (STORKSAMLEngineException e) {
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

	final STORKAuthnResponse response = new STORKAuthnResponse();
	response.setPersonalAttributeList(pal);

	try {
	    getEngine().generateSTORKAuthnResponse(authenRequest, response,
		    ipAddress, isHashing);
	    fail(ERROR_TXT);
	} catch (STORKSAMLEngineException e) {
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

	final STORKAuthnResponse response = new STORKAuthnResponse();
	response.setPersonalAttributeList(pal);
	try {
	    getEngine().generateSTORKAuthnResponse(authenRequest, response,
		    ipAddress, isHashing);
	    fail("generateAuthnResponse(...) should've thrown an STORKSAMLEngineException!");
	} catch (STORKSAMLEngineException e) {
	    authenRequest.setAssertionConsumerServiceURL(asserConsumerUrl);
	    LOG.error("Error");
	}
    }

    /**
     * Test generate authentication response IP address null.
     */
    @Test
    public final void testResponseValidationIP() {
	final STORKAuthnResponse response = new STORKAuthnResponse();
	response.setPersonalAttributeList(pal);

	try {
	    getEngine().generateSTORKAuthnResponse(authenRequest, response, null,
		    isHashing);
	    fail("generateAuthnResponse(...) should've thrown an STORKSAMLEngineException!");
	} catch (STORKSAMLEngineException e) {
	    LOG.error("Error");
	}
    }

    /**
     * Test generate authentication response with personal attribute list null.
     */
    @Test
    public final void testResponseMandatoryPersonalAttributeList() {
	final STORKAuthnResponse response = new STORKAuthnResponse();
	response.setPersonalAttributeList(null);
	
	
	try {
	    getEngine().generateSTORKAuthnResponse(authenRequest, response,
		    ipAddress, isHashing);
	    fail("generateAuthnResponse(...) should've thrown an STORKSAMLEngineException!");
	} catch (STORKSAMLEngineException e) {
	    LOG.error("Error");
	}
    }
    
    /**
     * Test validate authentication response token null.
     */
    @Test
    public final void testResponseInvalidParametersToken() {
	try {
	    getEngine().validateSTORKAuthnResponse(null, ipAddress, 0);
	    fail(ERROR_TXT);
	} catch (STORKSAMLEngineException e) {
	    LOG.error("Error");
	}
    }

    /**
     * Test validate authentication response IP null.
     */
    @Test
    public final void testResponseInvalidParametersIP() {
	final STORKAuthnResponse response = new STORKAuthnResponse();
	response.setPersonalAttributeList(pal);
	try {
	    authResponse = getEngine().generateSTORKAuthnResponse(authenRequest,
		    response, ipAddress, isNotHashing).getTokenSaml();
	    // In Conf1 ipValidate is false
	    getEngine().validateSTORKAuthnResponse(authResponse, null, 0);
	} catch (STORKSAMLEngineException e) {
	    LOG.error("Error");
	}
    }
    
    
    /**
     * Test validate authentication response parameter name wrong.
     */
    @Test
    public final void testResponseInvalidParametersAttr() {
	final STORKAuthnResponse response = new STORKAuthnResponse();
	final IPersonalAttributeList wrongList = new PersonalAttributeList();

	final PersonalAttribute worngAttr = new PersonalAttribute();
	worngAttr.setName("AttrWrong");
	wrongList.add(worngAttr);
	
	
	response.setPersonalAttributeList(wrongList);
	try {
	    authResponse = getEngine().generateSTORKAuthnResponse(authenRequest,
		    response, ipAddress, isNotHashing).getTokenSaml();
	    // In Conf1 ipValidate is false
	    getEngine().validateSTORKAuthnResponse(authResponse, null, 0);
	} catch (STORKSAMLEngineException e) {
	    LOG.error("Error");
	}
    }
    
    
    /**
     * Test validate authentication response set null value into attribute.
     */
    @Test
    public final void testResponseInvalidParametersAttrSimpleValue() {
	final STORKAuthnResponse response = new STORKAuthnResponse();
	final IPersonalAttributeList wrongList = new PersonalAttributeList();

	final PersonalAttribute worngAttr = new PersonalAttribute();
	worngAttr.setName("isAgeOver");
	worngAttr.setValue(null);
	wrongList.add(worngAttr);
	
	response.setPersonalAttributeList(wrongList);
	try {
	    authResponse = getEngine().generateSTORKAuthnResponse(authenRequest,
		    response, ipAddress, isNotHashing).getTokenSaml();
	    // In Conf1 ipValidate is false
	    getEngine().validateSTORKAuthnResponse(authResponse, null, 0);
	} catch (STORKSAMLEngineException e) {
	    LOG.error("Error");
	}
    }
    
    
    /**
     * Test validate authentication response set null value into attribute.
     */
    @Test
    public final void testResponseInvalidParametersAttrNoValue() {
	final STORKAuthnResponse response = new STORKAuthnResponse();
	final IPersonalAttributeList wrongList = new PersonalAttributeList();

	final PersonalAttribute worngAttr = new PersonalAttribute();
	worngAttr.setName("isAgeOver");
	wrongList.add(worngAttr);
	
	response.setPersonalAttributeList(wrongList);
	try {
	    authResponse = getEngine().generateSTORKAuthnResponse(authenRequest,
		    response, ipAddress, isNotHashing).getTokenSaml();
	    // In Conf1 ipValidate is false
	    getEngine().validateSTORKAuthnResponse(authResponse, null, 0);
	} catch (STORKSAMLEngineException e) {
	    LOG.error("Error");
	}
    }
    
    
    /**
     * Test validate authentication response set null value into attribute.
     */
    @Test
    public final void testResponseInvalidParametersAttrNoName() {
	final STORKAuthnResponse response = new STORKAuthnResponse();
	final IPersonalAttributeList wrongList = new PersonalAttributeList();

	final PersonalAttribute worngAttr = new PersonalAttribute();	
	wrongList.add(worngAttr);
	
	response.setPersonalAttributeList(wrongList);
	try {
	    authResponse = getEngine().generateSTORKAuthnResponse(authenRequest,
		    response, ipAddress, isNotHashing).getTokenSaml();
	    // In Conf1 ipValidate is false
	    getEngine().validateSTORKAuthnResponse(authResponse, null, 0);
	} catch (STORKSAMLEngineException e) {
	    LOG.error("Error");
	}
    }
    
    
    /**
     * Test validate authentication response set null complex value into attribute.
     */
    @Test
    public final void testResponseInvalidParametersAttrComplexValue() {
	final STORKAuthnResponse response = new STORKAuthnResponse();
	final IPersonalAttributeList wrongList = new PersonalAttributeList();

	final PersonalAttribute worngAttr = new PersonalAttribute();
	worngAttr.setName("isAgeOver");
	worngAttr.setComplexValue(null);
	wrongList.add(worngAttr);
	
	response.setPersonalAttributeList(wrongList);
	try {
	    authResponse = getEngine().generateSTORKAuthnResponse(authenRequest,
		    response, ipAddress, isNotHashing).getTokenSaml();
	    // In Conf1 ipValidate is false
	    getEngine().validateSTORKAuthnResponse(authResponse, null, 0);
	} catch (STORKSAMLEngineException e) {
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
		final STORKAuthnResponse response = new STORKAuthnResponse();
		response.setPersonalAttributeList(pal);

		final STORKAuthnResponse storkResponse = getEngine()
				.generateSTORKAuthnResponse(authenRequest, response, ipAddress,
						isNotHashing);

		authResponse = storkResponse.getTokenSaml();

		String responseAsString=new String (authResponse);
	    getEngine().validateSTORKAuthnResponse(authResponse, "127.0.0.1", 0);
	} catch (STORKSAMLEngineException e) {
	    LOG.error("Error");
	    fail("validateAuthenticationResponse(...) should've thrown an STORKSAMLEngineException!");
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
	    getEngine().validateSTORKAuthnResponse("errorMessage".getBytes(),
		    ipAddress, 0);
	    fail("validateAuthenticationResponse(...) should've thrown an STORKSAMLEngineException!");
	} catch (STORKSAMLEngineException e) {
	    LOG.error("Error");
	}
    }

    /**
     * Test validate authentication response is fail.
     * 
     * @throws STORKSAMLEngineException the STORKSAML engine exception
     */
    @Test
    public final void testValidateAuthenticationResponseIsFail()
	    throws STORKSAMLEngineException {
		testGenerateAuthnResponse();//prepare valid authnResponse
		authnResponse = getEngine().validateSTORKAuthnResponse(authResponse,
			ipAddress, 0);
		assertFalse("Generate incorrect response: ", authnResponse.isFail());
    }

    /**
     * Test validate authentication response destination.
     * 
     * @throws STORKSAMLEngineException the STORKSAML engine exception
     */
    @Test
    public final void testValidateAuthenticationResponseDestination()
	    throws STORKSAMLEngineException {
	authnResponse = getEngine().validateSTORKAuthnResponse(authResponse,
		ipAddress, 0);

	assertEquals("Destination incorrect: ",
		authnResponse.getInResponseTo(), authenRequest.getSamlId());
    }

    /**
     * Test validate authentication response values.
     * 
     * @throws STORKSAMLEngineException the STORKSAML engine exception
     */
    public final void testValidateAuthenticationResponseValuesComplex()
	    throws STORKSAMLEngineException {
	authnResponse = getEngine().validateSTORKAuthnResponse(authResponse,
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
     * @throws STORKSAMLEngineException 
     * 
     * @throws STORKSAMLEngineException the STORKSAML engine exception
     */
    @Test //( expected=STORKSAMLEngineException.class)
    public final void testGenerateAuthnResponseFailInResponseToNull() throws STORKSAMLEngineException {
	final String identifier = authenRequest.getSamlId();
	authenRequest.setSamlId(null);

	final STORKAuthnResponse response = new STORKAuthnResponse();
	response.setStatusCode(STORKStatusCode.REQUESTER_URI.toString());
	response.setSubStatusCode(STORKSubStatusCode.AUTHN_FAILED_URI.toString());
	response.setMessage("");

	try {
	    authResponse = getEngine().generateSTORKAuthnResponseFail(authenRequest,
		    response, ipAddress, isNotHashing).getTokenSaml();
	    fail(ERROR_TXT);
	} catch (STORKSAMLEngineException e) {
	    authenRequest.setSamlId(identifier);
	    LOG.error("Error");
	    //throw new STORKSAMLEngineException(e);
	}
    }

    /**
     * Test generate authenticate response fail assertion consumer URL err1.
     * 
     * @throws STORKSAMLEngineException the STORKSAML engine exception
     */
    @Test
    public final void testGenerateAuthnResponseFailAssertionConsumerUrlNull()
	    throws STORKSAMLEngineException {

	final String assertConsumerUrl = authenRequest
		.getAssertionConsumerServiceURL();
	authenRequest.setAssertionConsumerServiceURL(null);

	final STORKAuthnResponse response = new STORKAuthnResponse();
	response.setStatusCode(STORKStatusCode.REQUESTER_URI.toString());
	response.setSubStatusCode(STORKSubStatusCode.AUTHN_FAILED_URI.toString());
	response.setMessage("");

	try {
	    authResponse = getEngine().generateSTORKAuthnResponseFail(authenRequest,
		    response, ipAddress, isNotHashing).getTokenSaml();
	    fail("generateAuthnResponseFail(...) should've thrown an STORKSAMLEngineException!");
	} catch (STORKSAMLEngineException e) {
	    authenRequest.setAssertionConsumerServiceURL(assertConsumerUrl);
	    LOG.error("Error");
	}
    }

    /**
     * Test generate authentication response fail code error err1.
     * 
     * @throws STORKSAMLEngineException the STORKSAML engine exception
     */
    @Test
    public final void testGenerateAuthnResponseFailCodeErrorNull()
	    throws STORKSAMLEngineException {
	final STORKAuthnResponse response = new STORKAuthnResponse();
	response.setStatusCode(null);
	response.setSubStatusCode(STORKSubStatusCode.AUTHN_FAILED_URI.toString());
	response.setMessage("");

	try {
	    authResponse = getEngine().generateSTORKAuthnResponseFail(authenRequest,
		    response, ipAddress, isNotHashing).getTokenSaml();
	    fail("generateAuthnResponseFail(...) should've thrown an STORKSAMLEngineException!");
	} catch (STORKSAMLEngineException e) {
	    LOG.error("Error");
	}
    }
    
    
    
    
    /**
     * Test generate authentication request without errors.
     * 
     * @throws STORKSAMLEngineException the STORKSAML engine exception
     */
    @Test
    public final void testValidateAuthnResponse() throws STORKSAMLEngineException {
	
	IPersonalAttributeList palist = new PersonalAttributeList();

	PersonalAttribute isAgeOver = new PersonalAttribute();
	isAgeOver.setName("isAgeOver");
	isAgeOver.setIsRequired(true);
	ArrayList<String> ages = new ArrayList<String>();
	ages.add("16");
	ages.add("18");
	isAgeOver.setValue(ages);
	isAgeOver.setStatus(STORKStatusCode.STATUS_AVAILABLE.toString());
	palist.add(isAgeOver);

	PersonalAttribute dateOfBirth = new PersonalAttribute();
	dateOfBirth.setName("dateOfBirth");
	dateOfBirth.setIsRequired(false);
	final ArrayList<String> date = new ArrayList<String>();
	date.add("16/12/2008");
	dateOfBirth.setValue(date);
	dateOfBirth.setStatus(STORKStatusCode.STATUS_AVAILABLE.toString());
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
	
	eIDNumber.setStatus(STORKStatusCode.STATUS_NOT_AVAILABLE.toString());
	palist.add(eIDNumber);

	PersonalAttribute canRessAddress = new PersonalAttribute();	
	canRessAddress.setName("canonicalResidenceAddress");
	canRessAddress.setIsRequired(true);
	canRessAddress.setStatus(STORKStatusCode.STATUS_AVAILABLE.toString());
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

	
	final STORKAuthnResponse response = new STORKAuthnResponse();

	response.setPersonalAttributeList(palist);

	final STORKAuthnResponse storkResponse = getEngine()
		.generateSTORKAuthnResponse(authenRequest, response, ipAddress,
			isNotHashing);

	authResponse = storkResponse.getTokenSaml();
	LOG.info("Request id: " + authenRequest.getSamlId());
	
	LOG.info("RESPONSE: " + SSETestUtils.encodeSAMLToken(authResponse));
	
	
	authnResponse = getEngine().validateSTORKAuthnResponse(authResponse,
		ipAddress, 0);
	
	LOG.info("RESPONSE ID: " + authnResponse.getSamlId());
	LOG.info("RESPONSE IN_RESPONSE_TO: " + authnResponse.getInResponseTo());
	LOG.info("RESPONSE COUNTRY: " + authnResponse.getCountry());
	
    }
    
    
   

	
    /**
     * Test validate authentication response fail is fail.
     * 
     * @throws STORKSAMLEngineException the STORKSAML engine exception
     */
    @Test
    public final void testValidateAuthenticationResponseFailIsFail()
	    throws STORKSAMLEngineException {

	final STORKAuthnResponse response = new STORKAuthnResponse();
	response.setStatusCode(STORKStatusCode.REQUESTER_URI.toString());
	response.setSubStatusCode(STORKSubStatusCode.AUTHN_FAILED_URI.toString());
	response.setMessage("message");

	authResponse = getEngine().generateSTORKAuthnResponseFail(authenRequest,
		response, ipAddress, isNotHashing).getTokenSaml();
	
	LOG.error("ERROR_FAIL: " + PEPSUtil.encodeSAMLToken(authResponse));

	authnResponse = getEngine().validateSTORKAuthnResponse(authResponse,
		ipAddress, 0);

	LOG.info("COUNTRY: " + authnResponse.getCountry());
	assertTrue("Generate incorrect response: ", authnResponse.isFail());
    }  
    

	/**
	 *
	 * tests support for level of assurance
	 */
	@Test
	public final void testGenerateAuthnResponseLoA() throws STORKSAMLEngineException {

		final STORKAuthnResponse response = new STORKAuthnResponse();
		response.setPersonalAttributeList(pal);
		response.setAssuranceLevel("http://eidas.europa.eu/LoA/low");

		final STORKAuthnResponse storkResponse = getEngine().generateSTORKAuthnResponse(authenRequest, response, ipAddress, isNotHashing);

		authResponse = storkResponse.getTokenSaml();

		LOG.info("RESPONSE: " + SSETestUtils.encodeSAMLToken(authResponse));


	}

}
