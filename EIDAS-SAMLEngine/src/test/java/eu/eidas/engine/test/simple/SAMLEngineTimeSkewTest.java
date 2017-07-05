package eu.eidas.engine.test.simple;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.eidas.auth.commons.EIDASStatusCode;
import eu.eidas.auth.commons.EidasStringUtil;
import eu.eidas.auth.commons.PersonalAttribute;
import eu.eidas.auth.commons.attribute.AttributeDefinition;
import eu.eidas.auth.commons.attribute.ImmutableAttributeMap;
import eu.eidas.auth.commons.attribute.impl.StringAttributeValue;
import eu.eidas.auth.commons.protocol.IAuthenticationRequest;
import eu.eidas.auth.commons.protocol.IResponseMessage;
import eu.eidas.auth.commons.protocol.impl.AuthenticationResponse;
import eu.eidas.auth.commons.protocol.stork.IStorkAuthenticationRequest;
import eu.eidas.auth.commons.protocol.stork.impl.StorkAuthenticationRequest;
import eu.eidas.auth.engine.ProtocolEngineFactory;
import eu.eidas.auth.engine.ProtocolEngineI;
import eu.eidas.auth.engine.configuration.dom.ReloadableProtocolConfigurationInvocationHandler;
import eu.eidas.auth.engine.core.SAMLCore;
import eu.eidas.auth.engine.core.eidas.spec.NaturalPersonSpec;
import eu.eidas.auth.engine.core.stork.StorkExtensionProcessor;
import eu.eidas.auth.engine.core.validator.stork.STORKAttributes;
import eu.eidas.engine.exceptions.EIDASSAMLEngineException;

import static org.junit.Assert.fail;

/**
 *
 */
public class SAMLEngineTimeSkewTest {

    private static final Logger LOG = LoggerFactory.getLogger(SAMLEngineTimeSkewTest.class.getName());

    private SamlEngineTestClock clock;

    /**
     * The engines.
     */
    private ProtocolEngineI engine;

    @Before
    public void setUp() throws Exception {
        // inject a test clock to do some  time shifting
        engine =
                ProtocolEngineFactory.getDefaultProtocolEngine("SkewTest");
        InvocationHandler invocationHandler = Proxy.getInvocationHandler(engine.getClock());
        ReloadableProtocolConfigurationInvocationHandler ih = (ReloadableProtocolConfigurationInvocationHandler) invocationHandler;
        clock = (SamlEngineTestClock) ih.getProxiedObject();
    }

    /**
     * Normal behaviour of validation : no time skew, no clock change. Expected : no error
     *
     * @throws EIDASSAMLEngineException
     */
    @Test
    public void testValidateResponseWithNoTimeSkew() throws EIDASSAMLEngineException {
        LOG.info("testValidateResponseWithNoTimeSkew");
        clock.setDelta(0);
        byte[] samlResponse = generateTestSamlResponse();
        engine.unmarshallResponseAndValidate(samlResponse, "", 0, 0, null);
    }

    /**
     * Clock change to one hour later and no time skew Expected : exception thrown
     *
     * @throws EIDASSAMLEngineException
     */
    @Test(expected = EIDASSAMLEngineException.class)
    public void testValidateResponseWithTestClockOneHourLaterAndNoTimeSkew() throws EIDASSAMLEngineException {
        LOG.info("testValidateResponseWithTestClockOneHourLaterAndNoTimeSkew");
        clock.setDelta(600000);              // clock is now one hour later
        byte[] samlResponse = generateTestSamlResponse();
        engine.unmarshallResponseAndValidate(samlResponse, "", 0, 0, null);
    }

    /**
     * Clock change to one hour before and no time skew Expected : exception thrown
     *
     * @throws EIDASSAMLEngineException
     */
    @Test(expected = EIDASSAMLEngineException.class)
    public void testValidateResponseWithTestClockOneHourBeforeAndNoTimeSkew() throws EIDASSAMLEngineException {
        LOG.info("testValidateResponseWithTestClockOneHourBeforeAndNoTimeSkew");
        clock.setDelta(-600000);              // clock is now one hour before
        byte[] samlResponse = generateTestSamlResponse();
        engine.unmarshallResponseAndValidate(samlResponse, "", 0, 0, null);
    }

    /**
     * Clock change to one hour after and time skew one hour later Expected : no error
     *
     * @throws EIDASSAMLEngineException
     */
    @Test
    public void testValidateResponseWithTestClockOneHourLaterAndTimeSkew() throws EIDASSAMLEngineException {
        LOG.info("testValidateResponseWithTestClockOneHourLaterAndTimeSkew");
        clock.setDelta(600000);              // clock is now one hour later
        byte[] samlResponse = generateTestSamlResponse();
        engine.unmarshallResponseAndValidate(samlResponse, "", -600000, 600000, null);
    }

    private static PersonalAttribute newStorkPersonalAttribute(String friendlyName) {
        return new PersonalAttribute(SAMLCore.STORK10_BASE_URI.getValue() + friendlyName, friendlyName);
    }

    private static PersonalAttribute newEidasPersonalAttribute(String canoniclaName, String friendlyName) {
        return new PersonalAttribute(NaturalPersonSpec.Namespace.URI + "/" + canoniclaName, friendlyName);
    }

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

    private static ImmutableAttributeMap newResponseImmutableAttributeMap() {
        ImmutableAttributeMap.Builder builder = ImmutableAttributeMap.builder();

        AttributeDefinition<String> isAgeOver = (AttributeDefinition<String>) StorkExtensionProcessor.INSTANCE.getAttributeDefinitionNullable(
                STORKAttributes.STORK_ATTRIBUTE_ISAGEOVER);

        builder.put(isAgeOver, new StringAttributeValue("16", false), new StringAttributeValue("18", false));

        AttributeDefinition<String> dateOfBirth = (AttributeDefinition<String>) StorkExtensionProcessor.INSTANCE.getAttributeDefinitionNullable(
                STORKAttributes.STORK_ATTRIBUTE_DATEOFBIRTH);

        builder.put(dateOfBirth, new StringAttributeValue("16/12/2008", false));

        AttributeDefinition<String> eIdentifier = (AttributeDefinition<String>) StorkExtensionProcessor.INSTANCE.getAttributeDefinitionNullable(
                STORKAttributes.STORK_ATTRIBUTE_EIDENTIFIER);

        builder.put(eIdentifier, new StringAttributeValue("123456789P\u00D1", false));

        AttributeDefinition<String> canonicalResidenceAddress = (AttributeDefinition<String>) StorkExtensionProcessor.INSTANCE.getAttributeDefinitionNullable(
                STORKAttributes.STORK_ATTRIBUTE_TEXT_CANONICAL_ADDRESS);

        builder.put(canonicalResidenceAddress, new StringAttributeValue(getAddressValue(), false));

        return builder.build();
    }

    private byte[] generateTestSamlResponse() throws EIDASSAMLEngineException {

        String destination = "http://proxyservice.gov.xx/EidasNode/ColleagueRequest";
        String assertConsumerUrl = "http://connector.gov.xx/EidasNode/ColleagueResponse";

        String spName = "University of Oxford";
        String spSector = "EDU001";
        String spInstitution = "OXF001";
        String spApplication = "APP001";
        String spCountry = "EN";

        String spId = "EDU001-APP001-APP001";
        int QAAL = 3;

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
                requestedAttributes(newResponseImmutableAttributeMap()).
                levelOfAssurance("high").
                build();

        byte[] authRequest;
        IAuthenticationRequest authenRequest = null;

        try {
            authRequest = engine.generateRequestMessage(request, null).getMessageBytes();

            authenRequest = engine.unmarshallRequestAndValidate(authRequest, "ES");

        } catch (EIDASSAMLEngineException e) {
            fail("Error create EidasAuthenticationRequest");
        }

        String ipAddress = "111.222.333.444";

        ImmutableAttributeMap.Builder attributeMapBuilder = ImmutableAttributeMap.builder();

        AttributeDefinition<String> isAgeOverDef = (AttributeDefinition<String>) StorkExtensionProcessor.INSTANCE.getAttributeDefinitionNullable(
                STORKAttributes.STORK_ATTRIBUTE_ISAGEOVER);

        attributeMapBuilder.put(isAgeOverDef, new StringAttributeValue("16", false), new StringAttributeValue("18", false));

        AttributeDefinition<String> dateOfBirthDef = (AttributeDefinition<String>) StorkExtensionProcessor.INSTANCE.getAttributeDefinitionNullable(
                STORKAttributes.STORK_ATTRIBUTE_DATEOFBIRTH);

        attributeMapBuilder.put(dateOfBirthDef, new StringAttributeValue("16/12/2008", false));

        AttributeDefinition<String> eIdentifierDef = (AttributeDefinition<String>) StorkExtensionProcessor.INSTANCE.getAttributeDefinitionNullable(
                STORKAttributes.STORK_ATTRIBUTE_EIDENTIFIER);

        attributeMapBuilder.put(eIdentifierDef, new StringAttributeValue("123456789P\u00D1", false));

        AttributeDefinition<String> canonicalResidenceAddressDef = (AttributeDefinition<String>) StorkExtensionProcessor.INSTANCE.getAttributeDefinitionNullable(
                STORKAttributes.STORK_ATTRIBUTE_TEXT_CANONICAL_ADDRESS);

        Map<String, String> address = new HashMap<String, String>();
        address.put("state", "ES");
        address.put("municipalityCode", "MA001");
        address.put("town", "Madrid");
        address.put("postalCode", "28038");
        address.put("streetName", "Marchmalo");
        address.put("streetNumber", "33");
        address.put("apartamentNumber", "b");

        // TODO: fix this for STORK if needed:
        attributeMapBuilder.put(canonicalResidenceAddressDef, address.toString());

        AuthenticationResponse response = new AuthenticationResponse.Builder().id("RESPONSE_ID_TO_QDS2QFD")
                .inResponseTo("QDS2QFD")
                .issuer("http://Responder")
                .statusCode(EIDASStatusCode.SUCCESS_URI.toString())
                .levelOfAssurance("high")
                .ipAddress("123.123.123.123")
                .attributes(attributeMapBuilder.build())
                .build();

        IResponseMessage responseMessage = engine.generateResponseMessage(authenRequest, response, false, ipAddress);

        return responseMessage.getMessageBytes();
    }
}
