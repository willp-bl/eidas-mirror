package eu.eidas.engine.test.simple;

import eu.eidas.auth.commons.*;
import eu.eidas.auth.engine.EIDASSAMLEngine;
import eu.eidas.auth.engine.core.stork.StorkExtensionProcessor;
import eu.eidas.engine.exceptions.EIDASSAMLEngineException;

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
public class EidasSAMLEngineTimeSkewTest {
    private static final Logger LOG = LoggerFactory.getLogger(EidasSAMLEngineTimeSkewTest.class.getName());

    private SAMLEngineTestClock clock;

    /** The engines. */
    private static EIDASSAMLEngine engine = null;
    static{
        try{
            engine = EIDASSAMLEngine.createSAMLEngine("CONF1");
            engine.setExtensionProcessor(new StorkExtensionProcessor());
        }catch(EIDASSAMLEngineException e){
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
     * @throws EIDASSAMLEngineException
     */
    @Test
    public void testValidateResponseWithNoTimeSkew() throws EIDASSAMLEngineException{
        LOG.info("testValidateResponseWithNoTimeSkew");
        clock.setDelta(0);
        byte[] samlResponse = generateTestSamlResponse();
        engine.validateEIDASAuthnResponse(samlResponse, "", 0);
    }

    /**
     * Clock change to one hour later and no time skew
     * Expected : exception thrown
     * @throws EIDASSAMLEngineException
     */
    @Test ( expected=EIDASSAMLEngineException.class)
    public void testValidateResponseWithTestClockOneHourLaterAndNoTimeSkew() throws EIDASSAMLEngineException{
        LOG.info("testValidateResponseWithTestClockOneHourLaterAndNoTimeSkew");
        clock.setDelta(600000);              // clock is now one hour later
        byte[] samlResponse = generateTestSamlResponse();
        engine.validateEIDASAuthnResponse(samlResponse, "", 0);
    }

    /**
     * Clock change to one hour before and no time skew
     * Expected : exception thrown
     * @throws EIDASSAMLEngineException
     */
    @Test ( expected=EIDASSAMLEngineException.class)
    public void testValidateResponseWithTestClockOneHourBeforeAndNoTimeSkew() throws EIDASSAMLEngineException{
        LOG.info("testValidateResponseWithTestClockOneHourBeforeAndNoTimeSkew");
        clock.setDelta(-600000);              // clock is now one hour before
        byte[] samlResponse = generateTestSamlResponse();
        engine.validateEIDASAuthnResponse(samlResponse, "", 0);
    }

    /**
     * Clock change to one hour after and time skew one hour later
     * Expected : no error
     * @throws EIDASSAMLEngineException
     */
    @Test
    public void testValidateResponseWithTestClockOneHourLaterAndTimeSkew() throws EIDASSAMLEngineException{
        LOG.info("testValidateResponseWithTestClockOneHourLaterAndTimeSkew");
        clock.setDelta(600000);              // clock is now one hour later
        byte[] samlResponse = generateTestSamlResponse();
        engine.validateEIDASAuthnResponse(samlResponse, "", 600000);
    }



    private byte[] generateTestSamlResponse() throws EIDASSAMLEngineException {
        /** Parser manager used to parse XML. */
        BasicParserPool parser = EIDASSAMLEngine.getNewBasicSecuredParserPool();

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


        String destination = "http://proxyservice.gov.xx/EidasNode/ColleagueRequest";
        String assertConsumerUrl = "http://connector.gov.xx/EidasNode/ColleagueResponse";

        String spName = "University of Oxford";
        String spSector = "EDU001";
        String spInstitution = "OXF001";
        String spApplication = "APP001";
        String spCountry = "EN";

        String spId = "EDU001-APP001-APP001";
        int QAAL = 3;

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
        byte[] authRequest;
        EIDASAuthnRequest authenRequest=null;

        try {
            authRequest = engine.generateEIDASAuthnRequest(request)
                    .getTokenSaml();

            authenRequest = engine.validateEIDASAuthnRequest(authRequest);

        } catch (EIDASSAMLEngineException e) {
            fail("Error create EIDASAuthnRequest");
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

        address.put("state", "ES");
        address.put("municipalityCode", "MA001");
        address.put("town", "Madrid");
        address.put("postalCode", "28038");
        address.put("streetName", "Marchmalo");
        address.put("streetNumber", "33");
        address.put("apartamentNumber", "b");

        canRessAddress.setComplexValue(address);
        pal.add(canRessAddress);

        final EIDASAuthnResponse response = new EIDASAuthnResponse();
        response.setPersonalAttributeList(pal);

        final EIDASAuthnResponse eidasResponse = engine.generateEIDASAuthnResponse(authenRequest, response, ipAddress,
                        Boolean.FALSE);

        return eidasResponse.getTokenSaml();

    }
}
