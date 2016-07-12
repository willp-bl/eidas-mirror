package eu.stork.peps.test.simple;

import eu.stork.peps.auth.commons.*;
import eu.stork.peps.auth.engine.STORKSAMLEngine;
import eu.stork.peps.auth.engine.core.stork.StorkExtensionProcessor;
import eu.stork.peps.exceptions.STORKSAMLEngineException;
import org.junit.Before;
import org.junit.Test;

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.util.*;

import org.opensaml.xml.parse.BasicParserPool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;


/**
 *
 */
public class StorkSAMLEngineTimeSkewTest {
    private static final Logger LOG = LoggerFactory.getLogger(StorkSAMLEngineTimeSkewTest.class.getName());

    private SAMLEngineTestClock clock;

    /** The engines. */
    private static STORKSAMLEngine engine = null;
    static{
        try{
            engine = STORKSAMLEngine.createSTORKSAMLEngine("CONF1");
            engine.setExtensionProcessor(new StorkExtensionProcessor());
        }catch(STORKSAMLEngineException e){
            fail("Failed to initialize SAMLEngines");
        }
    }


    @Before
    public void setUp() throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException{
        // inject a test clock to do some  time shifting
        clock = new SAMLEngineTestClock();
        engine.setClock(clock);
    }

    /**
     * Normal behaviour of validation : no time skew, no clock change.
     * Expected : no error
     * @throws STORKSAMLEngineException
     */
    @Test
    public void testValidateResponseWithNoTimeSkew() throws STORKSAMLEngineException{
        LOG.info("testValidateResponseWithNoTimeSkew");
        clock.setDelta(0);
        byte[] samlResponse = generateTestSamlResponse();
        engine.validateSTORKAuthnResponse(samlResponse, "", 0);
    }

    /**
     * Clock change to one hour later and no time skew
     * Expected : exception thrown
     * @throws STORKSAMLEngineException
     */
    @Test ( expected=STORKSAMLEngineException.class)
    public void testValidateResponseWithTestClockOneHourLaterAndNoTimeSkew() throws STORKSAMLEngineException{
        LOG.info("testValidateResponseWithTestClockOneHourLaterAndNoTimeSkew");
        clock.setDelta(600000);              // clock is now one hour later
        byte[] samlResponse = generateTestSamlResponse();
        engine.validateSTORKAuthnResponse(samlResponse, "", 0);
    }

    /**
     * Clock change to one hour before and no time skew
     * Expected : exception thrown
     * @throws STORKSAMLEngineException
     */
    @Test ( expected=STORKSAMLEngineException.class)
    public void testValidateResponseWithTestClockOneHourBeforeAndNoTimeSkew() throws STORKSAMLEngineException{
        LOG.info("testValidateResponseWithTestClockOneHourBeforeAndNoTimeSkew");
        clock.setDelta(-600000);              // clock is now one hour before
        byte[] samlResponse = generateTestSamlResponse();
        engine.validateSTORKAuthnResponse(samlResponse, "", 0);
    }

    /**
     * Clock change to one hour after and time skew one hour later
     * Expected : no error
     * @throws STORKSAMLEngineException
     */
    @Test
    public void testValidateResponseWithTestClockOneHourLaterAndTimeSkew() throws STORKSAMLEngineException{
        LOG.info("testValidateResponseWithTestClockOneHourLaterAndTimeSkew");
        clock.setDelta(600000);              // clock is now one hour later
        byte[] samlResponse = generateTestSamlResponse();
        engine.validateSTORKAuthnResponse(samlResponse, "", 600000);
    }



    private byte[] generateTestSamlResponse() throws STORKSAMLEngineException {
        /** Parser manager used to parse XML. */
        BasicParserPool parser = STORKSAMLEngine.getNewBasicSecuredParserPool();

        IPersonalAttributeList pal = new PersonalAttributeList();

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


        String destination = "http://C-PEPS.gov.xx/PEPS/ColleagueRequest";
        String assertConsumerUrl = "http://S-PEPS.gov.xx/PEPS/ColleagueResponse";

        String spName = "University of Oxford";
        String spSector = "EDU001";
        String spInstitution = "OXF001";
        String spApplication = "APP001";
        String spCountry = "EN";

        String spId = "EDU001-APP001-APP001";
        int QAAL = 3;

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
        byte[] authRequest;
        STORKAuthnRequest authenRequest=null;

        try {
            authRequest = engine.generateSTORKAuthnRequest(request)
                    .getTokenSaml();

            authenRequest = engine.validateSTORKAuthnRequest(authRequest);

        } catch (STORKSAMLEngineException e) {
            fail("Error create STORKAuthnRequest");
        }

        String ipAddress = "111.222.333.444";

        pal = new PersonalAttributeList();

        isAgeOver = new PersonalAttribute();
        isAgeOver.setName("isAgeOver");
        isAgeOver.setIsRequired(true);
        ages = new ArrayList<String>();

        ages.add("16");
        ages.add("18");

        isAgeOver.setValue(ages);
        isAgeOver.setStatus(STORKStatusCode.STATUS_AVAILABLE.toString());
        pal.add(isAgeOver);

        dateOfBirth = new PersonalAttribute();
        dateOfBirth.setName("dateOfBirth");
        dateOfBirth.setIsRequired(false);
        final ArrayList<String> date = new ArrayList<String>();
        date.add("16/12/2008");
        dateOfBirth.setValue(date);
        dateOfBirth.setStatus(STORKStatusCode.STATUS_AVAILABLE.toString());
        pal.add(dateOfBirth);

        eIDNumber = new PersonalAttribute();
        eIDNumber.setName("eIdentifier");
        eIDNumber.setIsRequired(true);
        final ArrayList<String> idNumber = new ArrayList<String>();
        idNumber.add("123456789PÑ");
        eIDNumber.setValue(idNumber);
        eIDNumber.setStatus(STORKStatusCode.STATUS_AVAILABLE.toString());
        pal.add(eIDNumber);

        canRessAddress = new PersonalAttribute();
        canRessAddress.setName("canonicalResidenceAddress");
        canRessAddress.setIsRequired(true);
        canRessAddress.setStatus(STORKStatusCode.STATUS_AVAILABLE.toString());
        final HashMap<String, String> address = new HashMap<String, String>();

        address.put("state", "ES");
        address.put("municipalityCode", "MA001");
        address.put("town", "Madrid");
        address.put("postalCode", "28038");
        address.put("streetName", "Marchmalo");
        address.put("streetNumber", "33");
        address.put("apartamentNumber", "b");

        canRessAddress.setComplexValue(address);
        pal.add(canRessAddress);

        final STORKAuthnResponse response = new STORKAuthnResponse();
        response.setPersonalAttributeList(pal);

        final STORKAuthnResponse storkResponse = engine.generateSTORKAuthnResponse(authenRequest, response, ipAddress,
                        Boolean.FALSE);

        return storkResponse.getTokenSaml();

    }
}
