package eu.eidas.engine.test.simple.eidas;

import eu.eidas.auth.commons.EIDASAuthnRequest;
import eu.eidas.auth.commons.IPersonalAttributeList;
import eu.eidas.auth.commons.PersonalAttribute;
import eu.eidas.auth.commons.PersonalAttributeList;
import eu.eidas.auth.engine.EIDASSAMLEngine;
import eu.eidas.auth.engine.core.SAMLExtensionFormat;
import eu.eidas.engine.exceptions.EIDASSAMLEngineException;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;

import static org.junit.Assert.*;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

public class EidasMessageFormatOnlyTest {
    /**
     * The Constant LOG.
     */
    private static final Logger LOG = LoggerFactory.getLogger(EidasMessageFormatOnlyTest.class.getName());

    private EIDASSAMLEngine getEngine(String conf) {
        EIDASSAMLEngine engine = null;
        try {
            engine = EIDASSAMLEngine.createSAMLEngine(conf);
        } catch (EIDASSAMLEngineException exc) {
            fail("Failed to initialize SAMLEngines");
        }
        return engine;
    }
    private EIDASSAMLEngine getEngine(){
        return getEngine("EIDASONLY");
    }
    private EIDASSAMLEngine getStorkEngine(){
        return getEngine("CONF1");
    }


    /**
     * The destination.
     */
    private String destination;

    /**
     * The service provider name.
     */
    private String spName;

    /**
     * The service provider sector.
     */
    private String spSector;

    /**
     * The service provider institution.
     */
    private String spInstitution;

    /**
     * The service provider application.
     */
    private String spApplication;

    /**
     * The service provider country.
     */
    private String spCountry;

    /**
     * The service provider id.
     */
    private String spId;

    /**
     * The quality authentication assurance level.
     */
    private static final int QAAL = 3;

    /**
     * The List of Personal Attributes.
     */
    private IPersonalAttributeList pal;

    /**
     * The assertion consumer URL.
     */
    private String assertConsumerUrl;

    public EidasMessageFormatOnlyTest() {
        pal = new PersonalAttributeList();

        final PersonalAttribute isAgeOver = new PersonalAttribute();
        isAgeOver.setName("isAgeOver");
        isAgeOver.setIsRequired(true);
        final ArrayList<String> ages = new ArrayList<String>();
        ages.add("16");
        ages.add("18");
        isAgeOver.setValue(ages);
        pal.add(isAgeOver);

        final PersonalAttribute dateOfBirth = new PersonalAttribute();
        dateOfBirth.setName("dateOfBirth");
        dateOfBirth.setIsRequired(false);
        pal.add(dateOfBirth);

        final PersonalAttribute eIDNumber = new PersonalAttribute();
        eIDNumber.setName("eIdentifier");
        eIDNumber.setIsRequired(true);
        pal.add(eIDNumber);

        destination = "http://proxyservice.gov.xx/EidasNode/ColleagueRequest";
        assertConsumerUrl = "http://connector.gov.xx/EidasNode/ColleagueResponse";

        spName = "University of Oxford";
        spSector = "EDU001";
        spInstitution = "OXF001";
        spApplication = "APP001";
        spCountry = "EN";

        spId = "EDU001-OXF001-APP001";

    }



    @Test
    public void testMessageFormatForEidasOnly(){
        EIDASSAMLEngine engine = getEngine();
        assertNotNull(engine);
        assertTrue(engine.getExtensionProcessors().length== 1);
        byte[] request = null;
        try {
            request = generateStorkRequest();
        }catch(EIDASSAMLEngineException ee){
            fail("error during the generation of stork request: "+ee);
        }
        try{
            engine.validateEIDASAuthnRequest(request);
            fail("can validate stork request on eidas only processor");
        }catch(EIDASSAMLEngineException ee){

        }
        try{
            getStorkEngine().validateEIDASAuthnRequest(request);
        }catch(EIDASSAMLEngineException ee){
            fail("cannot validate stork request on multi processor engine");
        }
    }

    private byte[] generateStorkRequest() throws EIDASSAMLEngineException {

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
        request.setMessageFormatName(SAMLExtensionFormat.STORK1_FORMAT_NAME);


        return getStorkEngine().generateEIDASAuthnRequest(request).getTokenSaml();
    }


}
