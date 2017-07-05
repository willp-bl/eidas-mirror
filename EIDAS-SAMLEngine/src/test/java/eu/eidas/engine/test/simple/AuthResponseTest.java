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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;

import com.google.common.collect.ImmutableSet;

import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.eidas.auth.commons.EIDASStatusCode;
import eu.eidas.auth.commons.EIDASSubStatusCode;
import eu.eidas.auth.commons.EidasStringUtil;
import eu.eidas.auth.commons.PersonalAttribute;
import eu.eidas.auth.commons.PersonalAttributeList;
import eu.eidas.auth.commons.attribute.AttributeDefinition;
import eu.eidas.auth.commons.attribute.AttributeValue;
import eu.eidas.auth.commons.attribute.ImmutableAttributeMap;
import eu.eidas.auth.commons.attribute.PersonType;
import eu.eidas.auth.commons.attribute.impl.StringAttributeValue;
import eu.eidas.auth.commons.attribute.impl.StringAttributeValueMarshaller;
import eu.eidas.auth.commons.protocol.IAuthenticationRequest;
import eu.eidas.auth.commons.protocol.IAuthenticationResponse;
import eu.eidas.auth.commons.protocol.IResponseMessage;
import eu.eidas.auth.commons.protocol.impl.AuthenticationResponse;
import eu.eidas.auth.commons.protocol.stork.IStorkAuthenticationRequest;
import eu.eidas.auth.commons.protocol.stork.impl.StorkAuthenticationRequest;
import eu.eidas.auth.engine.ProtocolEngineFactory;
import eu.eidas.auth.engine.ProtocolEngineI;
import eu.eidas.auth.engine.core.SAMLCore;
import eu.eidas.auth.engine.core.eidas.spec.NaturalPersonSpec;
import eu.eidas.auth.engine.core.stork.StorkExtensionProcessor;
import eu.eidas.auth.engine.core.validator.stork.STORKAttributes;
import eu.eidas.engine.exceptions.EIDASSAMLEngineException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * The Class AuthRequestTest.
 */
public class AuthResponseTest {

    /**
     * The engine.
     */
    private static ProtocolEngineI engine = null;

    static {
            engine = ProtocolEngineFactory.getDefaultProtocolEngine("CONF2");
    }

    /**
     * Gets the engine.
     *
     * @return the engine
     */
    public static ProtocolEngineI getEngine() {
        return engine;
    }

    /**
     * Sets the engine.
     *
     * @param newEngine the new engine
     */
    public static void setEngine(final ProtocolEngineI newEngine) {
        AuthResponseTest.engine = newEngine;
    }

    /**
     * The destination.
     */
    private static String destination;

    /**
     * The service provider name.
     */
    private static String spName;

    /**
     * The service provider sector.
     */
    private static String spSector;

    /**
     * The service provider institution.
     */
    private static String spInstitution;

    /**
     * The service provider application.
     */
    private static String spApplication;

    /**
     * The service provider country.
     */
    private static String spCountry;

    /**
     * The service provider id.
     */
    private static String spId;

    /**
     * The quality authentication assurance level.
     */
    private static final int QAAL = 3;

    /**
     * The state.
     */
    private static String state = "ES";

    /**
     * The town.
     */
    private static String town = "Madrid";

    /**
     * The municipality code.
     */
    private static String municipalityCode = "MA001";

    /**
     * The postal code.
     */
    private static String postalCode = "28038";

    /**
     * The street name.
     */
    private static String streetName = "Marchamalo";

    /**
     * The street number.
     */
    private static String streetNumber = "3";

    /**
     * The apartament number.
     */
    private static String apartamentNumber = "5\u00BA E";

    /**
     * The Map of Personal Attributes.
     */
    private static ImmutableAttributeMap attributeMap;

    /**
     * The assertion consumer URL.
     */
    private static String assertConsumerUrl;

    /**
     * The authentication request.
     */
    private static byte[] authRequest;

    /**
     * The authentication response.
     */
    private static byte[] authResponse;

    /**
     * The authentication request.
     */
    private static IStorkAuthenticationRequest authenRequest;

    /**
     * The authentication response.
     */
    private static IAuthenticationResponse authnResponse;

    /**
     * The Constant LOG.
     */
    private static final Logger LOG = LoggerFactory.getLogger(AuthResponseTest.class.getName());

    /**
     * The IP address.
     */
    private static String ipAddress;

    /**
     * The ERROR text.
     */
    private static final String ERROR_TXT = "generateAuthnResponse(...) should've thrown an EIDASSAMLEngineException!";

    private static PersonalAttribute newStorkPersonalAttribute(String friendlyName) {
        return new PersonalAttribute(SAMLCore.STORK10_BASE_URI.getValue() + friendlyName, friendlyName);
    }

    private static PersonalAttribute newEidasPersonalAttribute(String canoniclaName, String friendlyName) {
        return new PersonalAttribute(NaturalPersonSpec.Namespace.URI + "/" + canoniclaName, friendlyName);
    }

    private static ImmutableAttributeMap newResponseImmutableAttributeMap() {
        ImmutableAttributeMap.Builder builder = ImmutableAttributeMap.builder();

        AttributeDefinition<String> isAgeOver = (AttributeDefinition<String>) StorkExtensionProcessor.INSTANCE.getAttributeDefinitionNullable(
                STORKAttributes.STORK_ATTRIBUTE_ISAGEOVER);

        builder.put(isAgeOver, new StringAttributeValue("16", false), new StringAttributeValue("18", false));

        AttributeDefinition<String> dateOfBirth = (AttributeDefinition<String>) StorkExtensionProcessor.INSTANCE.getAttributeDefinitionNullable(
                STORKAttributes.STORK_ATTRIBUTE_DATEOFBIRTH);

        builder.put(dateOfBirth, "16/12/2008");

        AttributeDefinition<String> eIdentifier = (AttributeDefinition<String>) StorkExtensionProcessor.INSTANCE.getAttributeDefinitionNullable(
                STORKAttributes.STORK_ATTRIBUTE_EIDENTIFIER);

        builder.put(eIdentifier, "123456789PÑ");

        AttributeDefinition<String> canonicalResidenceAddress = (AttributeDefinition<String>) StorkExtensionProcessor.INSTANCE.getAttributeDefinitionNullable(
                STORKAttributes.STORK_ATTRIBUTE_TEXT_CANONICAL_ADDRESS);

        builder.put(canonicalResidenceAddress, getAddressValue());

        return builder.build();
    }

    private static String getAddressValue() {
        Map<String, String> address = new LinkedHashMap<String, String>();
        address.put("state", state);
        address.put("municipalityCode", municipalityCode);
        address.put("town", town);
        address.put("postalCode", postalCode);
        address.put("streetName", streetName);
        address.put("streetNumber", streetNumber);
        address.put("apartamentNumber", apartamentNumber);
        return EidasStringUtil.encodeToBase64(address.toString());
    }

    static {

        PersonalAttributeList pal = new PersonalAttributeList();

        PersonalAttribute isAgeOver = newStorkPersonalAttribute("isAgeOver");
        isAgeOver.setIsRequired(false);
        ArrayList<String> ages = new ArrayList<String>();
        ages.add("16");
        ages.add("18");
        isAgeOver.setValue(ages);
        pal.add(isAgeOver);

        PersonalAttribute dateOfBirth = newStorkPersonalAttribute("dateOfBirth");
        dateOfBirth.setIsRequired(false);
        pal.add(dateOfBirth);

        PersonalAttribute eIDNumber = newStorkPersonalAttribute("eIdentifier");
        eIDNumber.setIsRequired(true);
        pal.add(eIDNumber);

        final PersonalAttribute givenName = newStorkPersonalAttribute("givenName");
        givenName.setIsRequired(true);
        pal.add(givenName);

        PersonalAttribute canRessAddress = newStorkPersonalAttribute("canonicalResidenceAddress");
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

        attributeMap = newResponseImmutableAttributeMap();

        IStorkAuthenticationRequest request = StorkAuthenticationRequest.builder().
                id("QDS2QFD"). // Common part
                assertionConsumerServiceURL(assertConsumerUrl).
                destination(destination).
                issuer("https://testIssuer").
                providerName(spName).
                serviceProviderCountryCode(spCountry).
                citizenCountryCode("ES").
                spId(spId).
                qaa(QAAL).
                spSector(spSector).
                spInstitution(spInstitution).
                spApplication(spApplication).
                requestedAttributes(attributeMap).
                levelOfAssurance("high").
                build();

        try {
            authRequest = getEngine().generateRequestMessage(request, null).getMessageBytes();

            authenRequest = (IStorkAuthenticationRequest) getEngine().unmarshallRequestAndValidate(authRequest,
                                                                                                   "ES");

        } catch (EIDASSAMLEngineException e) {
            e.printStackTrace();
            fail("Error create EidasAuthenticationRequest: " + e);
        }

        ipAddress = "111.222.333.444";
    }

    @SuppressWarnings({"PublicField"})
    @Rule
    public ExpectedException thrown = ExpectedException.none();

    /**
     * Test generate authentication request without errors.
     *
     * @throws EIDASSAMLEngineException the EIDASSAML engine exception
     */
    @Test
    public final void testGenerateAuthnResponse() throws EIDASSAMLEngineException {

        AuthenticationResponse response = new AuthenticationResponse.Builder().attributes(attributeMap)
                .id("963158")
                .inResponseTo(authenRequest.getId())
                .issuer("http://response.issuer")
                .ipAddress("123.123.123.123")
                .levelOfAssurance("high")
                .statusCode(EIDASStatusCode.SUCCESS_URI.toString())
                .build();

        IResponseMessage responseMessage = getEngine().generateResponseMessage(authenRequest, response, false, ipAddress);

        authResponse = responseMessage.getMessageBytes();
        String result = EidasStringUtil.toString(authResponse);
        LOG.info("RESPONSE: " + SSETestUtils.encodeSAMLToken(authResponse));
        LOG.info("RESPONSE as string: " + result);
    }

    /**
     * Test validation id parameter mandatory.
     */
    @Test(expected = IllegalArgumentException.class)
    public final void testResponseMandatoryId() throws Exception {
        IStorkAuthenticationRequest requestWithoutSamlId =
                StorkAuthenticationRequest.builder(authenRequest).id(null).build();
        AuthenticationResponse response = new AuthenticationResponse.Builder().attributes(attributeMap)
                .id("963158")
                .inResponseTo(authenRequest.getId())
                .issuer("http://response.issuer")
                .ipAddress("123.123.123.123")
                .levelOfAssurance("high")
                .statusCode(EIDASStatusCode.SUCCESS_URI.toString())
                .build();
        getEngine().generateResponseMessage(requestWithoutSamlId, response, false, ipAddress);
    }

    /**
     * Test generate authentication response in response to err1.
     */
    @Test(expected = IllegalArgumentException.class)
    public final void testResponseMandatoryIssuer() throws Exception {
        IAuthenticationRequest requestWithoutIssuer =
                StorkAuthenticationRequest.builder(authenRequest).issuer(null).build();
        AuthenticationResponse response = new AuthenticationResponse.Builder().attributes(attributeMap)
                .id("963158")
                .inResponseTo(authenRequest.getId())
                .issuer("http://response.issuer")
                .ipAddress("123.123.123.123")
                .levelOfAssurance("high")
                .statusCode(EIDASStatusCode.SUCCESS_URI.toString())
                .build();
        getEngine().generateResponseMessage(requestWithoutIssuer, response, false, ipAddress);
    }

    /**
     * Test generate authentication response assertion consumer null.
     */
    @Test
    public final void testResponseMandatoryAssertionConsumerServiceURL() throws Exception {

        thrown.expect(EIDASSAMLEngineException.class);
        thrown.expectMessage(
                "Error (no. message.validation.error.code) processing request : message.validation.error.code - Request AssertionConsumerServiceURL must not be blank.");

        IAuthenticationRequest request =
                StorkAuthenticationRequest.builder(authenRequest).assertionConsumerServiceURL(null).build();

        assertNull(request.getAssertionConsumerServiceURL());

        AuthenticationResponse response = new AuthenticationResponse.Builder().attributes(attributeMap)
                .id("963158")
                .inResponseTo(authenRequest.getId())
                .issuer("http://response.issuer")
                .ipAddress("123.123.123.123")
                .levelOfAssurance("high")
                .statusCode(EIDASStatusCode.SUCCESS_URI.toString())
                .build();

        getEngine().generateResponseMessage(request, response, false, ipAddress);
    }

    /**
     * Test generate authentication response IP address null.
     */
    @Test
    @Ignore
    public final void testResponseValidationIP() {
        AuthenticationResponse response = new AuthenticationResponse.Builder().attributes(attributeMap)
                .id("963158")
                .inResponseTo(authenRequest.getId())
                .issuer("http://response.issuer")
                .ipAddress("123.123.123.123")
                .levelOfAssurance("high")
                .statusCode(EIDASStatusCode.SUCCESS_URI.toString())
                .build();

        try {
            getEngine().generateResponseMessage(authenRequest, response, false, null);
            fail("generateAuthnResponse(...) should've thrown an EIDASSAMLEngineException!");
        } catch (EIDASSAMLEngineException e) {
            LOG.error("Error: " + e, e);
        }
    }

    /**
     * Test generate authentication response with personal attribute list null.
     */
    @Test
    public final void testResponseMandatoryPersonalAttributeList() {
        AuthenticationResponse response = AuthenticationResponse.builder()
                .id("789")
                .statusCode(EIDASStatusCode.SUCCESS_URI.toString())
                .inResponseTo("456")
                .issuer("http://response.issuer")
                .ipAddress("123.123.123.123")
                .levelOfAssurance("high")
                .build();

        try {
            getEngine().generateResponseMessage(authenRequest, response, false, ipAddress);
            fail("generateAuthnResponse(...) should've thrown an EIDASSAMLEngineException!");
        } catch (EIDASSAMLEngineException e) {
            LOG.error("Error: " + e, e);
        }
    }

    /**
     * Test validate authentication response token null.
     */
    @Test
    public final void testResponseInvalidParametersToken() {
        try {
            getEngine().unmarshallResponseAndValidate(null, ipAddress, 0, 0, null);
            fail(ERROR_TXT);
        } catch (EIDASSAMLEngineException e) {
            LOG.error("Error: " + e, e);
        }
    }

    /**
     * Test validate authentication response IP null.
     */
    @Test
    public final void testResponseInvalidParametersIP() {
        AuthenticationResponse response = new AuthenticationResponse.Builder().attributes(attributeMap)
                .id("963158")
                .inResponseTo(authenRequest.getId())
                .issuer("http://response.issuer")
                .ipAddress("123.123.123.123")
                .levelOfAssurance("high")
                .statusCode(EIDASStatusCode.SUCCESS_URI.toString())
                .build();
        try {
            authResponse = getEngine().generateResponseMessage(authenRequest, response, false, ipAddress).getMessageBytes();
            // In Conf1 ipValidate is false
            getEngine().unmarshallResponseAndValidate(authResponse, null, 0, 0, null);
        } catch (EIDASSAMLEngineException e) {
            LOG.error("Error: " + e, e);
        }
    }

    /**
     * Test validate authentication response parameter name wrong.
     */
    @Test
    public final void testResponseInvalidParametersAttr() {
        ImmutableAttributeMap attributeMap = ImmutableAttributeMap.builder()
                .put(new AttributeDefinition.Builder<String>().nameUri("urn:example.com/AttrWrong")
                             .friendlyName("AttrWrong")
                             .personType(PersonType.NATURAL_PERSON)
                             .xmlType("urn:example.com", "AttrWrongType", "wrong")
                             .attributeValueMarshaller(new StringAttributeValueMarshaller())
                             .build())
                .build();

        AuthenticationResponse response = new AuthenticationResponse.Builder().attributes(attributeMap)
                .id("963158")
                .inResponseTo(authenRequest.getId())
                .issuer("http://response.issuer")
                .ipAddress("123.123.123.123")
                .levelOfAssurance("high")
                .statusCode(EIDASStatusCode.SUCCESS_URI.toString())
                .build();

        try {
            authResponse = getEngine().generateResponseMessage(authenRequest, response, false, ipAddress).getMessageBytes();
            // In Conf1 ipValidate is false
            getEngine().unmarshallResponseAndValidate(authResponse, null, 0, 0, null);
            fail("generateResponseMessage(...) should've thrown an EIDASSAMLEngineException!");
        } catch (EIDASSAMLEngineException expected) {
            // expected
        }
    }

    /**
     * Test validate authentication response set null value into attribute.
     */
    @Test
    public final void testResponseInvalidParametersAttrSimpleValue() throws Exception {
        ImmutableAttributeMap.Builder wrongList = ImmutableAttributeMap.builder();

        AttributeDefinition isAgeOver = StorkExtensionProcessor.INSTANCE.getAttributeDefinitionNullable(
                STORKAttributes.STORK_ATTRIBUTE_ISAGEOVER);

        wrongList.put(isAgeOver, "");

        AuthenticationResponse response = new AuthenticationResponse.Builder().attributes(wrongList.build())
                .id("963158")
                .inResponseTo(authenRequest.getId())
                .issuer("http://response.issuer")
                .ipAddress("123.123.123.123")
                .levelOfAssurance("high")
                .statusCode(EIDASStatusCode.SUCCESS_URI.toString())
                .build();

        try {
            authResponse = getEngine().generateResponseMessage(authenRequest, response, false, ipAddress).getMessageBytes();
            // In Conf1 ipValidate is false
            getEngine().unmarshallResponseAndValidate(authResponse, null, 0, 0, null);
        } catch (EIDASSAMLEngineException e) {
            LOG.error("Error " + e, e);
        }
    }

    /**
     * Test validate authentication response set null value into attribute.
     */
    @Test
    public final void testResponseInvalidParametersAttrNoValue() throws Exception {
        ImmutableAttributeMap.Builder wrongList = ImmutableAttributeMap.builder();

        AttributeDefinition isAgeOver = StorkExtensionProcessor.INSTANCE.getAttributeDefinitionNullable(
                STORKAttributes.STORK_ATTRIBUTE_ISAGEOVER);

        wrongList.put(isAgeOver);

        AuthenticationResponse response = new AuthenticationResponse.Builder().attributes(wrongList.build())
                .id("963158")
                .inResponseTo(authenRequest.getId())
                .issuer("http://response.issuer")
                .ipAddress("123.123.123.123")
                .levelOfAssurance("high")
                .statusCode(EIDASStatusCode.SUCCESS_URI.toString())
                .build();

        try {
            authResponse = getEngine().generateResponseMessage(authenRequest, response, false, ipAddress).getMessageBytes();
            // In Conf1 ipValidate is false
            getEngine().unmarshallResponseAndValidate(authResponse, null, 0, 0, null);
        } catch (EIDASSAMLEngineException e) {
            LOG.error("Error " + e, e);
        }
    }

    /**
     * Test validate authentication response set null value into attribute.
     */
    @Test
    public final void testResponseInvalidParametersAttrNoName() throws Exception {
        ImmutableAttributeMap.Builder wrongList = ImmutableAttributeMap.builder();

        AuthenticationResponse response = new AuthenticationResponse.Builder().attributes(wrongList.build())
                .id("963158")
                .inResponseTo(authenRequest.getId())
                .issuer("http://response.issuer")
                .ipAddress("123.123.123.123")
                .levelOfAssurance("high")
                .statusCode(EIDASStatusCode.SUCCESS_URI.toString())
                .build();

        try {
            authResponse = getEngine().generateResponseMessage(authenRequest, response, false, ipAddress).getMessageBytes();
            // In Conf1 ipValidate is false
            getEngine().unmarshallResponseAndValidate(authResponse, null, 0, 0,null);
        } catch (EIDASSAMLEngineException e) {
            LOG.error("Error " + e, e);
        }
    }

    /**
     * Test validate authentication response set null complex value into attribute.
     */
    @Test
    public final void testResponseInvalidParametersAttrComplexValue() throws Exception {
        ImmutableAttributeMap.Builder wrongList = ImmutableAttributeMap.builder();

        AttributeDefinition isAgeOver = StorkExtensionProcessor.INSTANCE.getAttributeDefinitionNullable(
                STORKAttributes.STORK_ATTRIBUTE_ISAGEOVER);

        wrongList.put(isAgeOver);

        AuthenticationResponse response = new AuthenticationResponse.Builder().attributes(wrongList.build())
                .id("963158")
                .inResponseTo(authenRequest.getId())
                .issuer("http://response.issuer")
                .ipAddress("123.123.123.123")
                .levelOfAssurance("high")
                .statusCode(EIDASStatusCode.SUCCESS_URI.toString())
                .build();
        try {
            authResponse = getEngine().generateResponseMessage(authenRequest, response, false, ipAddress).getMessageBytes();
            // In Conf1 ipValidate is false
            getEngine().unmarshallResponseAndValidate(authResponse, null, 0, 0, null);
        } catch (EIDASSAMLEngineException e) {
            LOG.error("Error " + e, e);
        }
    }

    /**
     * Test validate authentication response IP distinct and disabled validation IP.
     */
    @Test
    public final void testResponseInvalidParametersIPDistinct() {
        try {
            // ipAddress origin "111.222.33.44"
            // ipAddrValidation = false
            // Subject Confirmation Bearer.

            getEngine().unmarshallResponseAndValidate(authResponse, "127.0.0.1", 0, 0, null);
        } catch (EIDASSAMLEngineException e) {
            LOG.error("Error: " + e, e);
            fail("validateAuthenticationResponse(...) should've thrown an EIDASSAMLEngineException!: " + e);
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
            getEngine().unmarshallResponseAndValidate(EidasStringUtil.getBytes("errorMessage"), ipAddress, 0, 0, null);
            fail("validateAuthenticationResponse(...) should've thrown an EIDASSAMLEngineException!");
        } catch (EIDASSAMLEngineException e) {
            LOG.error("Error: " + e, e);
        }
    }

    /**
     * Test validate authentication response is fail.
     *
     * @throws EIDASSAMLEngineException the EIDASSAML engine exception
     */
    @Test
    public final void testValidateAuthenticationResponseIsFail() throws EIDASSAMLEngineException {
        testGenerateAuthnResponse();//prepare valid authnResponse
        authnResponse = getEngine().unmarshallResponseAndValidate(authResponse, ipAddress, 0, 0, null);
        assertFalse("Generate incorrect response: ", authnResponse.isFailure());
    }

    /**
     * Test validate authentication response destination.
     *
     * @throws EIDASSAMLEngineException the EIDASSAML engine exception
     */
    @Test
    public final void testValidateAuthenticationResponseDestination() throws EIDASSAMLEngineException {
        authnResponse = getEngine().unmarshallResponseAndValidate(authResponse, ipAddress, 0, 0, null);

        assertEquals("Destination incorrect: ", authnResponse.getInResponseToId(), authenRequest.getId());
    }

    /**
     * Test validate authentication response values.
     *
     * @throws EIDASSAMLEngineException the EIDASSAML engine exception
     */
    public final void testValidateAuthenticationResponseValuesComplex() throws EIDASSAMLEngineException {
        authnResponse = getEngine().unmarshallResponseAndValidate(authResponse, ipAddress, 0, 0, null);

        assertEquals("Country incorrect:", authnResponse.getCountry(), "EN");

        for (final Map.Entry<AttributeDefinition<?>, ImmutableSet<? extends AttributeValue<?>>> entry : authnResponse.getAttributes()
                .getAttributeMap()
                .entrySet()) {

            AttributeDefinition<?> attributeDefinition = entry.getKey();
            ImmutableSet<? extends AttributeValue<?>> values = entry.getValue();

            if ("canonicalResidenceAddress".equalsIgnoreCase(attributeDefinition.getFriendlyName())) {
                String value = (String) values.iterator().next().getValue();

                assertEquals("Incorrect STORK address: ", getAddressValue(), value);
            }
        }
    }

    /**
     * Test generate authenticate response fail in response to it's null.
     *
     * @throws EIDASSAMLEngineException
     * @throws EIDASSAMLEngineException the EIDASSAML engine exception
     */
    @Test(expected = IllegalArgumentException.class)
    public final void testGenerateAuthnResponseFailInResponseToNull() throws EIDASSAMLEngineException {
        IAuthenticationRequest request = StorkAuthenticationRequest.builder(authenRequest).id(null).build();

        AuthenticationResponse.Builder response = new AuthenticationResponse.Builder();
        response.statusCode(EIDASStatusCode.REQUESTER_URI.toString());
        response.subStatusCode(EIDASSubStatusCode.AUTHN_FAILED_URI.toString());
        response.statusMessage("");
        response.id("963158");
        response.inResponseTo(authenRequest.getId());
        response.issuer("http://response.issuer");
        response.ipAddress("123.123.123.123");
        response.levelOfAssurance("high");
        response.statusCode(EIDASStatusCode.SUCCESS_URI.toString());

        try {
            authResponse =
                    getEngine().generateResponseErrorMessage(request, response.build(), ipAddress).getMessageBytes();
            fail(ERROR_TXT);
        } catch (EIDASSAMLEngineException e) {
            LOG.error("Error: " + e, e);
        }
    }

    /**
     * Test generate authenticate response fail assertion consumer URL err1.
     *
     * @throws EIDASSAMLEngineException the EIDASSAML engine exception
     */
    @Test
    public final void testGenerateAuthnResponseFailAssertionConsumerUrlNull() throws EIDASSAMLEngineException {

        IAuthenticationRequest request =
                StorkAuthenticationRequest.builder(authenRequest).assertionConsumerServiceURL(null).build();

        AuthenticationResponse.Builder response = new AuthenticationResponse.Builder();
        response.statusCode(EIDASStatusCode.REQUESTER_URI.toString());
        response.subStatusCode(EIDASSubStatusCode.AUTHN_FAILED_URI.toString());
        response.statusMessage("");
        response.id("963158");
        response.inResponseTo(authenRequest.getId());
        response.issuer("http://response.issuer");
        response.ipAddress("123.123.123.123");
        response.levelOfAssurance("high");
        response.statusCode(EIDASStatusCode.SUCCESS_URI.toString());

        try {
            authResponse =
                    getEngine().generateResponseErrorMessage(request, response.build(), ipAddress).getMessageBytes();
            fail("generateAuthnResponseFail(...) should've thrown an EIDASSAMLEngineException!");
        } catch (EIDASSAMLEngineException e) {
            LOG.error("Error: " + e, e);
        }
    }

    /**
     * Test generate authentication response fail code error err1.
     */
    @Test
    public final void testGenerateAuthnResponseFailCodeErrorNull() throws Exception {

        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("statusCode cannot be null, empty or blank");

        AuthenticationResponse.Builder response = new AuthenticationResponse.Builder();
        response.statusCode(null);
        response.subStatusCode(EIDASSubStatusCode.AUTHN_FAILED_URI.toString());
        response.statusMessage("Error message");
        response.id("963158");
        response.inResponseTo(authenRequest.getId());
        response.issuer("http://response.issuer");
        response.ipAddress("123.123.123.123");
        response.levelOfAssurance("high");

        authResponse =
                getEngine().generateResponseErrorMessage(authenRequest, response.build(), ipAddress).getMessageBytes();
    }

    /**
     * Test generate authentication request without errors.
     *
     * @throws EIDASSAMLEngineException the EIDASSAML engine exception
     */
    @Test
    public final void testValidateAuthnResponse() throws EIDASSAMLEngineException {

        AuthenticationResponse.Builder response = new AuthenticationResponse.Builder();
        response.attributes(newResponseImmutableAttributeMap());
        response.id("963158");
        response.inResponseTo(authenRequest.getId());
        response.issuer("http://response.issuer");
        response.ipAddress("123.123.123.123");
        response.levelOfAssurance("high");
        response.statusCode(EIDASStatusCode.SUCCESS_URI.toString());

        IResponseMessage responseMessage =
                getEngine().generateResponseMessage(authenRequest, response.build(), false, ipAddress);

        authResponse = responseMessage.getMessageBytes();
        LOG.info("Request id: " + authenRequest.getId());

        LOG.info("RESPONSE: " + SSETestUtils.encodeSAMLToken(authResponse));

        authnResponse = getEngine().unmarshallResponseAndValidate(authResponse, ipAddress, 0, 0, null);

        LOG.info("RESPONSE ID: " + authnResponse.getId());
        LOG.info("RESPONSE IN_RESPONSE_TO: " + authnResponse.getInResponseToId());
        LOG.info("RESPONSE COUNTRY: " + authnResponse.getCountry());

    }

    /**
     * Test validate authentication response fail is fail.
     *
     * @throws EIDASSAMLEngineException the EIDASSAML engine exception
     */
    @Test
    public final void testValidateAuthenticationResponseFailIsFail() throws EIDASSAMLEngineException {

        AuthenticationResponse.Builder response = new AuthenticationResponse.Builder();
        response.statusCode(EIDASStatusCode.REQUESTER_URI.toString());
        response.failure(true);
        response.subStatusCode(EIDASSubStatusCode.AUTHN_FAILED_URI.toString());
        response.statusMessage("message");
        response.id("963158");
        response.inResponseTo(authenRequest.getId());
        response.issuer("http://response.issuer");
        response.ipAddress("123.123.123.123");
        response.levelOfAssurance("high");

        authResponse =
                getEngine().generateResponseErrorMessage(authenRequest, response.build(), ipAddress).getMessageBytes();

        LOG.error("ERROR_FAIL: " + EidasStringUtil.encodeToBase64(authResponse));

        authnResponse = getEngine().unmarshallResponseAndValidate(authResponse, ipAddress, 0, 0, null);

        LOG.info("COUNTRY: " + authnResponse.getCountry());
        assertTrue("Generate incorrect response: ", authnResponse.isFailure());
    }

    /**
     * Test generate/validate response with signedDoc
     *
     * @throws EIDASSAMLEngineException the EIDASSAML engine exception
     */
    @Test
    public final void testGenerateAuthenResponseWithSignedDoc() throws EIDASSAMLEngineException {

        String signedDocResponse =
                "<dss:SignResponse xmlns:dss=\"urn:oasis:names:tc:dss:1.0:core:schema\" RequestID=\"123456\"> <dss:Result> <dss:ResultMajor>urn:oasis:names:tc:dss:1.0:resultmajor:Success</dss:ResultMajor> </dss:Result> <dss:SignatureObject> <dss:Base64Signature Type=\"urn:ietf:rfc:3275\">PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48ZHM6U2lnbmF0dXJlIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIiBJZD0iU2lnbmF0dXJlLThlYWJkMGE1LTY2MGQtNGFmZC05OTA1LTBhYmM3NTUzZDE5Mi1TaWduYXR1cmUiPjxkczpTaWduZWRJbmZvPjxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvVFIvMjAwMS9SRUMteG1sLWMxNG4tMjAwMTAzMTUiLz48ZHM6U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3JzYS1zaGExIi8+PGRzOlJlZmVyZW5jZSBJZD0iUmVmZXJlbmNlLWJhYmE0ZDFhLWExN2UtNDJjNi05N2QyLWJlZWUxMzUwOTUwMyIgVHlwZT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI09iamVjdCIgVVJJPSIjT2JqZWN0LTk4NzMzY2RlLThiY2MtNDhhMC05Yjc3LTBlOTk5N2JkZDA1OCI+PGRzOlRyYW5zZm9ybXM+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNiYXNlNjQiLz48L2RzOlRyYW5zZm9ybXM+PGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNzaGExIi8+PGRzOkRpZ2VzdFZhbHVlPkNrMVZxTmQ0NVFJdnEzQVpkOFhZUUx2RWh0QT08L2RzOkRpZ2VzdFZhbHVlPjwvZHM6UmVmZXJlbmNlPjxkczpSZWZlcmVuY2UgVHlwZT0iaHR0cDovL3VyaS5ldHNpLm9yZy8wMTkwMyNTaWduZWRQcm9wZXJ0aWVzIiBVUkk9IiNTaWduYXR1cmUtOGVhYmQwYTUtNjYwZC00YWZkLTk5MDUtMGFiYzc1NTNkMTkyLVNpZ25lZFByb3BlcnRpZXMiPjxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjc2hhMSIvPjxkczpEaWdlc3RWYWx1ZT5BNVk5MW40cXBMZ3l0VFc3ZnhqWENVZVJ2NTQ9PC9kczpEaWdlc3RWYWx1ZT48L2RzOlJlZmVyZW5jZT48ZHM6UmVmZXJlbmNlIFVSST0iI1NpZ25hdHVyZS04ZWFiZDBhNS02NjBkLTRhZmQtOTkwNS0wYWJjNzU1M2QxOTItS2V5SW5mbyI+PGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNzaGExIi8+PGRzOkRpZ2VzdFZhbHVlPlZQWDRuS0Z5UzZyRitGNmNSUjBQck5aZHc2Zz08L2RzOkRpZ2VzdFZhbHVlPjwvZHM6UmVmZXJlbmNlPjwvZHM6U2lnbmVkSW5mbz48ZHM6U2lnbmF0dXJlVmFsdWUgSWQ9IlNpZ25hdHVyZS04ZWFiZDBhNS02NjBkLTRhZmQtOTkwNS0wYWJjNzU1M2QxOTItU2lnbmF0dXJlVmFsdWUiPkxiS04vL0M3WGt5eFR0WVRpQ1VScjhuWnp4QW1zdGNNZDBDZ0VBQ3JLMWR5Z1JIcUdjSzR4dHMrV0NVOFB5RXFXclJJVFl6SXV3LzcNClY0Wno5VFQ2MHA0S1RNZXd1UUw2NHNrRVN4MllnMkVkaWtTTyt0S3hXa2hyYVVzbVZiR2JQbW1jbUR2OTd0SER3ODg3NDdlRnE1RjUNCnYrYVZTeUF6MDNpVUttdVNlSDg9PC9kczpTaWduYXR1cmVWYWx1ZT48ZHM6S2V5SW5mbyBJZD0iU2lnbmF0dXJlLThlYWJkMGE1LTY2MGQtNGFmZC05OTA1LTBhYmM3NTUzZDE5Mi1LZXlJbmZvIj48ZHM6S2V5VmFsdWU+PGRzOlJTQUtleVZhbHVlPjxkczpNb2R1bHVzPnd1Y21qOXRJV3J2d2JTVFVEZndLbCtKdERNTUVSMGNMZDZEa0JTcjc5MHQrckdOakVTcVlqUndFSWVCbktvUUhQeDVIb1JlRjg4L3QNCnFZOStDaEVYcExITHM5cDVhWDdTREp1YnBRTWZwMXRERlgzNHl3Z3hTUXZjZWVKUVdCWGppZXVJbWZDMjFzNGJPY2dKYlYxaGJpZ1MNCnpPS1RRS3IxVHpkR1IrdVJ5MDA9PC9kczpNb2R1bHVzPjxkczpFeHBvbmVudD5BUUFCPC9kczpFeHBvbmVudD48L2RzOlJTQUtleVZhbHVlPjwvZHM6S2V5VmFsdWU+PGRzOlg1MDlEYXRhPjxkczpYNTA5Q2VydGlmaWNhdGU+TUlJSW1UQ0NCNEdnQXdJQkFnSURBWFVVTUEwR0NTcUdTSWIzRFFFQkJRVUFNSUlCT3pFTE1Ba0dBMVVFQmhNQ1JWTXhPekE1QmdOVg0KQkFvVE1rRm5aVzVqYVdFZ1EyRjBZV3hoYm1FZ1pHVWdRMlZ5ZEdsbWFXTmhZMmx2SUNoT1NVWWdVUzB3T0RBeE1UYzJMVWtwTVRRdw0KTWdZRFZRUUhFeXRRWVhOellYUm5aU0JrWlNCc1lTQkRiMjVqWlhCamFXOGdNVEVnTURnd01EZ2dRbUZ5WTJWc2IyNWhNUzR3TEFZRA0KVlFRTEV5VlRaWEoyWldseklGQjFZbXhwWTNNZ1pHVWdRMlZ5ZEdsbWFXTmhZMmx2SUVWRFZpMHlNVFV3TXdZRFZRUUxFeXhXWldkbA0KZFNCb2RIUndjem92TDNkM2R5NWpZWFJqWlhKMExtNWxkQzkyWlhKRFNVTXRNaUFvWXlrd016RTFNRE1HQTFVRUN4TXNSVzUwYVhSaA0KZENCd2RXSnNhV05oSUdSbElHTmxjblJwWm1sallXTnBieUJrWlNCamFYVjBZV1JoYm5NeEd6QVpCZ05WQkFNVEVsQlNSVkJTVDBSVg0KUTBOSlR5QkpSRU5oZERBZUZ3MHhNREF5TVRFeE9ESXlNRFJhRncweE5EQXlNVEF4T0RJeU1EUmFNSUd3TVFzd0NRWURWUVFHRXdKRg0KVXpFMU1ETUdBMVVFQ3hNc1ZtVm5aWFVnYUhSMGNITTZMeTkzZDNjdVkyRjBZMlZ5ZEM1dVpYUXZkbVZ5U1VSRFlYUWdLR01wTURNeA0KRmpBVUJnTlZCQVFURFVKRlVreEJUa2RCSUZOUFZFOHhGekFWQmdOVkJDb1REazFCVWtsQklFVk9SMUpCUTBsQk1SSXdFQVlEVlFRRg0KRXdreE1EQXdNRGswTkZNeEpUQWpCZ05WQkFNVEhFMUJVa2xCSUVWT1IxSkJRMGxCSUVKRlVreEJUa2RCSUZOUFZFOHdnWjh3RFFZSg0KS29aSWh2Y05BUUVCQlFBRGdZMEFNSUdKQW9HQkFNTG5Kby9iU0ZxNzhHMGsxQTM4Q3BmaWJRekRCRWRIQzNlZzVBVXErL2RMZnF4ag0KWXhFcW1JMGNCQ0hnWnlxRUJ6OGVSNkVYaGZQUDdhbVBmZ29SRjZTeHk3UGFlV2wrMGd5Ym02VURINmRiUXhWOStNc0lNVWtMM0huaQ0KVUZnVjQ0bnJpSm53dHRiT0d6bklDVzFkWVc0b0VzemlrMENxOVU4M1JrZnJrY3ROQWdNQkFBR2pnZ1N3TUlJRXJEQU1CZ05WSFJNQg0KQWY4RUFqQUFNQTRHQTFVZER3RUIvd1FFQXdJRm9EQ0J6QVlEVlIwUkJJSEVNSUhCZ1E5aWMyOTBiMEJuYldGcGJDNWpiMjJrZ1lVdw0KZ1lJeEN6QUpCZ05WQkFZVEFrVlRNU3N3S1FZRFZRUUtGQ0pCWjhPb2JtTnBZU0JEWVhSaGJHRnVZU0JrWlNCRFpYSjBhV1pwWTJGag0KYWNPek1RNHdEQVlEVlFRTEV3VkpSRU5CVkRFUE1BMEdBMVVFQlJNR01ERTNOVEUwTVNVd0l3WURWUVFERXh4TlFWSkpRU0JGVGtkUw0KUVVOSlFTQkNSVkpNUVU1SFFTQlRUMVJQb0JBR0Npc0dBUVFCOVhnQkFRR2dBZ3dBb0JRR0RsWUVBQUVEQmdFRUFmVjRBUUVDb0FJTQ0KQURBZkJnTlZIUklFR0RBV2dSUmxZMTlwWkdOaGRFQmpZWFJqWlhKMExtNWxkREFkQmdOVkhRNEVGZ1FVQUZYanVOc2tCMk1seXZVQg0KaDdwOFRKMHVKMHd3Z2dGSUJnTlZIU01FZ2dFL01JSUJPNEFVUkt2Y2tVaE4xNGg0Q24vZ2RPRG42NzIzS1Z5aGdnRVBwSUlCQ3pDQw0KQVFjeEN6QUpCZ05WQkFZVEFrVlRNVHN3T1FZRFZRUUtFekpCWjJWdVkybGhJRU5oZEdGc1lXNWhJR1JsSUVObGNuUnBabWxqWVdOcA0KYnlBb1RrbEdJRkV0TURnd01URTNOaTFKS1RFb01DWUdBMVVFQ3hNZlUyVnlkbVZwY3lCUWRXSnNhV056SUdSbElFTmxjblJwWm1sag0KWVdOcGJ6RThNRG9HQTFVRUN4TXpWbVZuWlhVZ2FIUjBjSE02THk5M2QzY3VZMkYwWTJWeWRDNXVaWFF2ZG1WeWNISmxjSEp2WkhWag0KWTJsdklDaGpLVEF6TVRVd013WURWUVFMRXl4S1pYSmhjbkYxYVdFZ1JXNTBhWFJoZEhNZ1pHVWdRMlZ5ZEdsbWFXTmhZMmx2SUVOaA0KZEdGc1lXNWxjekVjTUJvR0ExVUVBeE1UVUZKRlVGSlBSRlZEUTBsUElFVkRMVUZEUTRJUWR3S1R0TTFFRVU5RkVQWFVZSGdnaERBZA0KQmdOVkhTVUVGakFVQmdnckJnRUZCUWNEQWdZSUt3WUJCUVVIQXdRd0VRWUpZSVpJQVliNFFnRUJCQVFEQWdXZ01EUUdDQ3NHQVFVRg0KQndFQkJDZ3dKakFrQmdnckJnRUZCUWN3QVlZWWFIUjBjSE02THk5dlkzTndMbU5oZEdObGNuUXVibVYwTUJnR0NDc0dBUVVGQndFRA0KQkF3d0NqQUlCZ1lFQUk1R0FRRXdnWVlHQTFVZEh3Ui9NSDB3UEtBNm9EaUdObWgwZEhBNkx5OWxjSE5qWkM1allYUmpaWEowTG01bA0KZEM5amNtd3ZjSEpsY0hKdlpIVmpZMmx2WDJWakxXbGtZMkYwTG1OeWJEQTlvRHVnT1lZM2FIUjBjRG92TDJWd2MyTmtNaTVqWVhSag0KWlhKMExtNWxkQzlqY213dmNISmxjSEp2WkhWalkybHZYMlZqTFdsa1kyRjBMbU55YkRDQjlnWURWUjBnQklIdU1JSHJNSUhvQmd3cg0KQmdFRUFmVjRBUU1CVmdFd2dkY3dMQVlJS3dZQkJRVUhBZ0VXSUdoMGRIQnpPaTh2ZDNkM0xtTmhkR05sY25RdWJtVjBMM1psY2tsRQ0KUTJGME1JR21CZ2dyQmdFRkJRY0NBakNCbVJxQmxrRnhkV1Z6ZENEdnY3MXpJSFZ1SUdObGNuUnBabWxqWVhRZ2NHVnljMjl1WVd3Zw0KU1VSRFFWUXNJSEpsWTI5dVpXZDFkQ0JrSjJsa1pXNTBhV1pwWTJGajc3KzlMQ0J6YVdkdVlYUjFjbUVnYVNCNGFXWnlZWFFnWkdVZw0KWTJ4aGMzTmxJRElnYVc1a2FYWnBaSFZoYkM0Z1ZtVm5aWFVnYUhSMGNITTZMeTkzZDNjdVkyRjBZMlZ5ZEM1dVpYUXZkbVZ5UkVOaA0KZERBdEJnTlZIUWtFSmpBa01CQUdDQ3NHQVFVRkJ3a0VNUVFUQWtWVE1CQUdDQ3NHQVFVRkJ3a0ZNUVFUQWtWVE1BMEdDU3FHU0liMw0KRFFFQkJRVUFBNElCQVFDcTc3ODBSR1FNTEIxZ2tkTk1mTFhuZ3FNb1JIR0taYnZ6a3JxSUFtVDhXQWQxRThyQXBoUjkveExKVXRwNQ0KbGJnMmZScjVibDJqOE9WREJLMlltRzQxaDhBRG40U1RJL0FwZU5JTlNmalpzNk5Sc25XekZ5ZlhYbVBDSFlGQi9YV3p5aW1DRXhndg0KdnR1SCszUUF3Y3dobjUwUExFdWh3NUM1dmxYN0x5NUs2ckxMTUZOVVVNYldWeTFoWmVsSy9DQlRjQWpJTzM4TlkrdllSQU1LU2Y0TQ0KL2daUXo0cUJlRlZKYTUyUjdOY0FxQ2ZyZkxmYVhwYkRTZzk4eG9CZU5zMmluR3p4OFVTZ0VyTFpqS0pzZG4vS2pURDlnUy9zVGRRNg0KUTdpZHFsZDJMRlZsTzIvYjk0Wk5aQmNTLzc4RU9EWGdkV2ZreVBDN1J3OHJlOW5JMy9qVDwvZHM6WDUwOUNlcnRpZmljYXRlPjwvZHM6WDUwOURhdGE+PC9kczpLZXlJbmZvPjxkczpPYmplY3QgRW5jb2Rpbmc9ImJhc2U2NCIgSWQ9Ik9iamVjdC05ODczM2NkZS04YmNjLTQ4YTAtOWI3Ny0wZTk5OTdiZGQwNTgiIE1pbWVUeXBlPSJhcHBsaWNhdGlvbi9vY3RldC1zdHJlYW0iPlNHVnNiRzhnVjI5eWJHUT08L2RzOk9iamVjdD48ZHM6T2JqZWN0Pjx4YWRlczpRdWFsaWZ5aW5nUHJvcGVydGllcyB4bWxuczp4YWRlcz0iaHR0cDovL3VyaS5ldHNpLm9yZy8wMTkwMy92MS4zLjIjIiBJZD0iU2lnbmF0dXJlLThlYWJkMGE1LTY2MGQtNGFmZC05OTA1LTBhYmM3NTUzZDE5Mi1RdWFsaWZ5aW5nUHJvcGVydGllcyIgVGFyZ2V0PSIjU2lnbmF0dXJlLThlYWJkMGE1LTY2MGQtNGFmZC05OTA1LTBhYmM3NTUzZDE5Mi1TaWduYXR1cmUiPjx4YWRlczpTaWduZWRQcm9wZXJ0aWVzIElkPSJTaWduYXR1cmUtOGVhYmQwYTUtNjYwZC00YWZkLTk5MDUtMGFiYzc1NTNkMTkyLVNpZ25lZFByb3BlcnRpZXMiPjx4YWRlczpTaWduZWRTaWduYXR1cmVQcm9wZXJ0aWVzPjx4YWRlczpTaWduaW5nVGltZT4yMDExLTAzLTIxVDExOjQ0OjQyKzAxOjAwPC94YWRlczpTaWduaW5nVGltZT48eGFkZXM6U2lnbmluZ0NlcnRpZmljYXRlPjx4YWRlczpDZXJ0Pjx4YWRlczpDZXJ0RGlnZXN0PjxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjc2hhMSIvPjxkczpEaWdlc3RWYWx1ZT4zbTZ3OTlUb3lTZDlKcEJsMWdCazhEei9iYlU9PC9kczpEaWdlc3RWYWx1ZT48L3hhZGVzOkNlcnREaWdlc3Q+PHhhZGVzOklzc3VlclNlcmlhbD48ZHM6WDUwOUlzc3Vlck5hbWU+Q049UFJFUFJPRFVDQ0lPIElEQ2F0LCBPVT1FbnRpdGF0IHB1YmxpY2EgZGUgY2VydGlmaWNhY2lvIGRlIGNpdXRhZGFucywgT1U9VmVnZXUgaHR0cHM6Ly93d3cuY2F0Y2VydC5uZXQvdmVyQ0lDLTIgKGMpMDMsIE9VPVNlcnZlaXMgUHVibGljcyBkZSBDZXJ0aWZpY2FjaW8gRUNWLTIsIEw9UGFzc2F0Z2UgZGUgbGEgQ29uY2VwY2lvIDExIDA4MDA4IEJhcmNlbG9uYSwgTz1BZ2VuY2lhIENhdGFsYW5hIGRlIENlcnRpZmljYWNpbyAoTklGIFEtMDgwMTE3Ni1JKSwgQz1FUzwvZHM6WDUwOUlzc3Vlck5hbWU+PGRzOlg1MDlTZXJpYWxOdW1iZXI+OTU1MDg8L2RzOlg1MDlTZXJpYWxOdW1iZXI+PC94YWRlczpJc3N1ZXJTZXJpYWw+PC94YWRlczpDZXJ0PjwveGFkZXM6U2lnbmluZ0NlcnRpZmljYXRlPjwveGFkZXM6U2lnbmVkU2lnbmF0dXJlUHJvcGVydGllcz48eGFkZXM6U2lnbmVkRGF0YU9iamVjdFByb3BlcnRpZXM+PHhhZGVzOkRhdGFPYmplY3RGb3JtYXQgT2JqZWN0UmVmZXJlbmNlPSIjUmVmZXJlbmNlLWJhYmE0ZDFhLWExN2UtNDJjNi05N2QyLWJlZWUxMzUwOTUwMyI+PHhhZGVzOk1pbWVUeXBlPmFwcGxpY2F0aW9uL29jdGV0LXN0cmVhbTwveGFkZXM6TWltZVR5cGU+PHhhZGVzOkVuY29kaW5nPmJhc2U2NDwveGFkZXM6RW5jb2Rpbmc+PC94YWRlczpEYXRhT2JqZWN0Rm9ybWF0PjwveGFkZXM6U2lnbmVkRGF0YU9iamVjdFByb3BlcnRpZXM+PC94YWRlczpTaWduZWRQcm9wZXJ0aWVzPjwveGFkZXM6UXVhbGlmeWluZ1Byb3BlcnRpZXM+PC9kczpPYmplY3Q+PC9kczpTaWduYXR1cmU+</dss:Base64Signature> </dss:SignatureObject> </dss:SignResponse>";

        ImmutableAttributeMap.Builder builder = ImmutableAttributeMap.builder();

        AttributeDefinition<String> isAgeOver = (AttributeDefinition<String>) StorkExtensionProcessor.INSTANCE.getAttributeDefinitionNullable(
                STORKAttributes.STORK_ATTRIBUTE_ISAGEOVER);

        builder.put(isAgeOver, new StringAttributeValue("16", false), new StringAttributeValue("18", false));

        AttributeDefinition<String> signedDoc = (AttributeDefinition<String>) StorkExtensionProcessor.INSTANCE.getAttributeDefinitionNullable(
                STORKAttributes.STORK_ATTRIBUTE_SIGNEDDOC);

        builder.put(signedDoc, signedDocResponse);

        ImmutableAttributeMap attributes = builder.build();

        IAuthenticationRequest request =
                StorkAuthenticationRequest.builder(authenRequest).requestedAttributes(attributes).build();

        AttributeDefinition<String> isAgeOverDef = (AttributeDefinition<String>) StorkExtensionProcessor.INSTANCE.getAttributeDefinitionNullable(
                STORKAttributes.STORK_ATTRIBUTE_ISAGEOVER);

        AttributeDefinition<String> signedDocDef = (AttributeDefinition<String>) StorkExtensionProcessor.INSTANCE.getAttributeDefinitionNullable(
                STORKAttributes.STORK_ATTRIBUTE_SIGNEDDOC);

        AttributeDefinition<String> eIdentifier = (AttributeDefinition<String>) StorkExtensionProcessor.INSTANCE.getAttributeDefinitionNullable(
                STORKAttributes.STORK_ATTRIBUTE_EIDENTIFIER);

        ImmutableAttributeMap attributeMap = ImmutableAttributeMap.builder()
                .put(eIdentifier, "1234564")
                .put(isAgeOverDef, new StringAttributeValue("16", false), new StringAttributeValue("18", false))
                .put(signedDocDef, signedDocResponse)
                .build();

        AuthenticationResponse response = new AuthenticationResponse.Builder().attributes(attributeMap)
                .id("963158")
                .inResponseTo(authenRequest.getId())
                .issuer("http://response.issuer")
                .ipAddress("123.123.123.123")
                .levelOfAssurance("high")
                .statusCode(EIDASStatusCode.SUCCESS_URI.toString())
                .build();

        IResponseMessage responseMessage = getEngine().generateResponseMessage(request, response, false, ipAddress);

        authResponse = responseMessage.getMessageBytes();
        authnResponse = getEngine().unmarshallResponseAndValidate(authResponse, ipAddress, 0, 0, null);

        assertEquals("SignedDoc response should be the same: ", signedDocResponse, authnResponse.getAttributes()
                .getAttributeValuesByFriendlyName("signedDoc")
                .getAttributeMap()
                .values()
                .iterator()
                .next()
                .iterator()
                .next().getValue());

    }

}
