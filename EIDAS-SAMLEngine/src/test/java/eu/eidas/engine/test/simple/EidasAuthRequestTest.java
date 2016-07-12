/* 
 * Licensed under the EUPL, Version 1.1 or – as soon they will be approved by
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

import static org.junit.Assert.*;

import java.nio.charset.Charset;
import java.util.ArrayList;

import eu.eidas.auth.commons.IPersonalAttributeList;
import eu.eidas.auth.commons.PersonalAttribute;
import eu.eidas.auth.commons.PersonalAttributeList;
import eu.eidas.auth.commons.EIDASAuthnRequest;
import eu.eidas.auth.engine.EIDASSAMLEngine;
import eu.eidas.auth.engine.core.SAMLExtensionFormat;
import eu.eidas.auth.engine.core.stork.StorkExtensionProcessor;
import eu.eidas.engine.exceptions.EIDASSAMLEngineException;

import org.junit.Test;
import org.opensaml.xml.parse.BasicParserPool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The Class EidasAuthRequestTest - test support for STORK1 format.
 */
public class EidasAuthRequestTest {

    /**
     * The engines.
     */
    private static EIDASSAMLEngine engine = null;

    private static EIDASSAMLEngine engine2 = null;
    private static EIDASSAMLEngine engine3 = null;
    static{
        try{
            engine=EIDASSAMLEngine.createSAMLEngine("CONF1");
            engine.setExtensionProcessor(new StorkExtensionProcessor());
            engine2 = EIDASSAMLEngine.createSAMLEngine("CONF2");
            engine2.setExtensionProcessor(new StorkExtensionProcessor());
            engine3 = EIDASSAMLEngine.createSAMLEngine("CONF3");
            engine3.setExtensionProcessor(new StorkExtensionProcessor());
        }catch(EIDASSAMLEngineException exc){
            fail("Failed to initialize SAMLEngines");
        }
    }

    private EIDASSAMLEngine getEngine(){
        return helperGetEngine("CONF1");
    }

    private EIDASSAMLEngine getEngine2(){
        return helperGetEngine("CONF2");
    }

    private EIDASSAMLEngine getEngine3(){
        return helperGetEngine("CONF3");
    }

    private EIDASSAMLEngine helperGetEngine(String name){
        EIDASSAMLEngine engine = null;
        try {
            engine = EIDASSAMLEngine.createSAMLEngine(name);
            engine.setExtensionProcessor(new StorkExtensionProcessor());
        }catch(EIDASSAMLEngineException exc){
            fail("Failed to initialize SAMLEngines");
        }
        return engine;

    }

    /**
     * Instantiates a new authentication request test.
     */
    public EidasAuthRequestTest() {
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

    /**
     * The authentication request.
     */
    private static byte[] authRequest;

    /**
     * The Constant LOG.
     */
    private static final Logger LOG = LoggerFactory
            .getLogger(EidasAuthRequestTest.class.getName());

    /**
     * Parser manager used to parse XML.
     */
    private static BasicParserPool parser;

    static {
        parser = EIDASSAMLEngine.getNewBasicSecuredParserPool();
    }

    /**
     * Test generate authentication request.
     *
     * @throws EIDASSAMLEngineException the EIDASSAML engine exception
     */
    @Test
    public final void testGenerateAuthnRequest() throws EIDASSAMLEngineException {

        final EIDASAuthnRequest request = new EIDASAuthnRequest();

        request.setDestination(destination);
        request.setProviderName(spName);
        request.setQaa(QAAL);
        request.setPersonalAttributeList(pal);
        request.setAssertionConsumerServiceURL(assertConsumerUrl);

        // new parameters
        request.setSpSector(spSector);
        request.setSpInstitution(spInstitution);
        request.setSpApplication(spApplication);
        request.setSpCountry(spCountry);
        request.setSPID(spId);
        request.setCitizenCountryCode("ES");


        LOG.info("EIDASAuthnRequest 1: " + SSETestUtils.encodeSAMLToken(engine.generateEIDASAuthnRequest(request).getTokenSaml()));
        request.setCitizenCountryCode("ES");
        LOG.info("EIDASAuthnRequest 2: " + SSETestUtils.encodeSAMLToken(engine.generateEIDASAuthnRequest(request).getTokenSaml()));
    }


    /**
     * Test generate authentication request error personal attribute name error.
     */
    @Test
    public final void testGenerateAuthnRequestPALsErr1() {

        final IPersonalAttributeList palWrong = new PersonalAttributeList();

        final PersonalAttribute worngAttr = new PersonalAttribute();
        worngAttr.setName("attrNotValid");
        worngAttr.setIsRequired(true);

        final EIDASAuthnRequest request = new EIDASAuthnRequest();

        request.setDestination(destination);
        request.setProviderName(spName);
        request.setQaa(QAAL);
        request.setPersonalAttributeList(palWrong);
        request.setAssertionConsumerServiceURL(assertConsumerUrl);

        // news parameters
        request.setSpSector(spSector);
        request.setSpInstitution(spInstitution);
        request.setSpApplication(spApplication);
        request.setSpCountry(spCountry);
        request.setSPID(spId);
        request.setCitizenCountryCode("ES");

        try {
            engine.generateEIDASAuthnRequest(request);
            fail("generateEIDASAuthnRequest(...) should've thrown an EIDASSAMLEngineException!");
        } catch (EIDASSAMLEngineException e) {
            LOG.error("Error");
        }
    }


    /**
     * Test generate authentication request error personal attribute value error.
     */
    @Test
    public final void testGenerateAuthnRequestPALsErr2() {

        final IPersonalAttributeList palWrong = new PersonalAttributeList();

        final PersonalAttribute attrNotValid = new PersonalAttribute();
        attrNotValid.setName("attrNotValid");
        attrNotValid.setIsRequired(true);
        palWrong.add(attrNotValid);


        final EIDASAuthnRequest request = new EIDASAuthnRequest();

        request.setDestination(destination);
        request.setProviderName(spName);
        request.setQaa(QAAL);
        request.setPersonalAttributeList(palWrong);
        request.setAssertionConsumerServiceURL(assertConsumerUrl);

        // news parameters
        request.setSpSector(spSector);
        request.setSpInstitution(spInstitution);
        request.setSpApplication(spApplication);
        request.setSpCountry(spCountry);
        request.setSPID(spId);
        request.setCitizenCountryCode("ES");

        try {
            engine.generateEIDASAuthnRequest(request);
            fail("generateEIDASAuthnRequest(...) should've thrown an EIDASSAMLEngineException!");
        } catch (EIDASSAMLEngineException e) {
            LOG.error("Error");
        }
    }

    /**
     * Test generate authentication request error provider name null.
     */
    @Test
    public final void testGenerateAuthnRequestSPNAmeErr1() {


        final EIDASAuthnRequest request = new EIDASAuthnRequest();

        request.setDestination(destination);
        request.setProviderName(null);
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
            engine.generateEIDASAuthnRequest(request);
            fail("generateEIDASAuthnRequest(...) should've thrown an EIDASSAMLEngineException!");
        } catch (EIDASSAMLEngineException e) {
            LOG.error("Error");
        }
    }

    /**
     * Test generate authentication request authentication assurance level
     * negative value.
     */
    @Test
    public final void testGenerateAuthnRequestQaalErr1() {

        final EIDASAuthnRequest request = new EIDASAuthnRequest();

        request.setDestination(destination);
        request.setProviderName(spName);
        request.setQaa(-1);
        request.setPersonalAttributeList(pal);
        request.setAssertionConsumerServiceURL(assertConsumerUrl);

        // news parameters
        request.setSpSector(spSector);
        request.setSpInstitution(spInstitution);
        request.setSpApplication(spApplication);
        request.setSpCountry(spCountry);
        request.setSPID(spId);

        try {
            engine.generateEIDASAuthnRequest(request);
            fail("generateEIDASAuthnRequest(...) should've thrown an EIDASSAMLEngineException!");
        } catch (EIDASSAMLEngineException e) {
            LOG.error("Error");
        }
    }

    /**
     * Test generate authentication request service provider sector null.
     */
    @Test
    public final void testGenerateAuthnRequestSectorErr() {

        final EIDASAuthnRequest request = new EIDASAuthnRequest();

        request.setDestination(destination);
        request.setProviderName(spName);
        request.setQaa(QAAL);
        request.setPersonalAttributeList(pal);
        request.setAssertionConsumerServiceURL(assertConsumerUrl);

        // news parameters
        request.setSpSector(null);
        request.setSpInstitution(spInstitution);
        request.setSpApplication(spApplication);
        request.setSpCountry(spCountry);
        request.setSPID(spId);
        request.setCitizenCountryCode("ES");

        try {
            engine.generateEIDASAuthnRequest(request);
        } catch (EIDASSAMLEngineException e) {
            LOG.error("Error");
            fail("generateEIDASAuthnRequest(...) should've thrown an EIDASSAMLEngineException!");

        }
    }

    /**
     * Test generate authentication request service provider institution null.
     */
    @Test
    public final void testGenerateAuthnRequestInstitutionrErr() {

        final EIDASAuthnRequest request = new EIDASAuthnRequest();

        request.setDestination(destination);
        request.setProviderName(spName);
        request.setQaa(QAAL);
        request.setPersonalAttributeList(pal);
        request.setAssertionConsumerServiceURL(assertConsumerUrl);

        // news parameters
        request.setSpSector(spSector);
        request.setSpInstitution(null);
        request.setSpApplication(spApplication);
        request.setSpCountry(spCountry);
        request.setSPID(spId);
        request.setCitizenCountryCode("ES");

        try {
            engine.generateEIDASAuthnRequest(request);

        } catch (EIDASSAMLEngineException e) {
            LOG.error("Error");
            fail("generateEIDASAuthnRequest(...) should've thrown an EIDASSAMLEngineException!");
        }
    }

    /**
     * Test generate authentication request service provider application null.
     */
    @Test
    public final void testGenerateAuthnRequestApplicationErr() {

        final EIDASAuthnRequest request = new EIDASAuthnRequest();

        request.setDestination(destination);
        request.setProviderName(spName);
        request.setQaa(QAAL);
        request.setPersonalAttributeList(pal);
        request.setAssertionConsumerServiceURL(assertConsumerUrl);

        // news parameters
        request.setSpSector(spSector);
        request.setSpInstitution(spInstitution);
        request.setSpApplication(null);
        request.setSpCountry(spCountry);
        request.setSPID(spId);
        request.setCitizenCountryCode("ES");

        try {
            engine.generateEIDASAuthnRequest(request);

        } catch (EIDASSAMLEngineException e) {
            LOG.error("Error");
            fail("generateEIDASAuthnRequest(...) should've thrown an EIDASSAMLEngineException!");
        }
    }

    /**
     * Test generate authentication request service provider country null.
     */
    @Test
    public final void testGenerateAuthnRequestCountryErr() {

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
        request.setSpCountry(null);
        request.setSPID(spId);
        request.setCitizenCountryCode("ES");

        try {
            engine.generateEIDASAuthnRequest(request);

        } catch (EIDASSAMLEngineException e) {
            LOG.error("Error");
            fail("generateEIDASAuthnRequest(...) should've thrown an EIDASSAMLEngineException!");
        }
    }

    /**
     * Test generate authentication request error with quality authentication
     * assurance level wrong.
     */
    @Test
    public final void testGenerateAuthnRequestQaalErr2() {
        final EIDASAuthnRequest request = new EIDASAuthnRequest();

        request.setDestination(destination);
        request.setProviderName(spName);
        request.setQaa(0);
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
            engine.setExtensionProcessor(new StorkExtensionProcessor());
            engine.generateEIDASAuthnRequest(request);
            fail("generateEIDASAuthnRequest(...) should've thrown an EIDASSAMLEngineException!");
        } catch (EIDASSAMLEngineException e) {
            LOG.error("Error");
        }
    }

    /**
     * Test generate authentication request personal attribute list null value.
     */
    @Test
    public final void testGenerateAuthnRequestPALErr1() {
        final EIDASAuthnRequest request = new EIDASAuthnRequest();

        request.setDestination(destination);
        request.setProviderName(spName);
        request.setQaa(QAAL);
        request.setPersonalAttributeList(null);
        request.setAssertionConsumerServiceURL(assertConsumerUrl);

        // news parameters
        request.setSpSector(spSector);
        request.setSpInstitution(spInstitution);
        request.setSpApplication(spApplication);
        request.setSpCountry(spCountry);
        request.setSPID(spId);
        request.setCitizenCountryCode("ES");

        try {
            engine.generateEIDASAuthnRequest(request);
            fail("generateEIDASAuthnRequest(...) should've thrown an EIDASSAMLEngineException!");
        } catch (EIDASSAMLEngineException e) {
            LOG.error("Error");
        }
    }

    /**
     * Test generate authentication request error with assertion consumer URL
     * null.
     */
    @Test
    public final void testGenerateAuthnRequestAssertionConsumerErr1() {
        final EIDASAuthnRequest request = new EIDASAuthnRequest();

        request.setDestination(destination);
        request.setProviderName(spName);
        request.setQaa(QAAL);
        request.setPersonalAttributeList(pal);
        request.setAssertionConsumerServiceURL(null);

        // news parameters
        request.setSpSector(spSector);
        request.setSpInstitution(spInstitution);
        request.setSpApplication(spApplication);
        request.setSpCountry(spCountry);
        request.setSPID(spId);
        request.setCitizenCountryCode("ES");

        try {
            engine.setExtensionProcessor(new StorkExtensionProcessor());
            engine.generateEIDASAuthnRequest(request);
            fail("generateEIDASAuthnRequest(...) should've thrown an EIDASSAMLEngineException!");
        } catch (EIDASSAMLEngineException e) {
            LOG.error("Error");
        }
    }

    /**
     * Test validate authentication request null parameter.
     *
     * @throws EIDASSAMLEngineException the EIDASSAML engine exception
     */
    @Test
    public final void testValidateAuthnRequestNullParam()
            throws EIDASSAMLEngineException {
        try {
            engine.validateEIDASAuthnRequest(null);
            fail("validateEIDASAuthnRequest(...) should've thrown an EIDASSAMLEngineException!");
        } catch (EIDASSAMLEngineException e) {
            LOG.error("Error");
        }
    }

    /**
     * Test validate authentication request error bytes encode.
     *
     * @throws EIDASSAMLEngineException the EIDASSAML engine exception
     */
    @Test
    public final void testValidateAuthnRequestErrorEncode()
            throws EIDASSAMLEngineException {
        try {
            engine.validateEIDASAuthnRequest("messageError".getBytes());
            fail("validateEIDASAuthnRequest(...) should've thrown an EIDASSAMLEngineException!");
        } catch (EIDASSAMLEngineException e) {
            LOG.error("Error");
        }
    }

    /**
     * Test validate authentication request.
     *
     * @throws EIDASSAMLEngineException the EIDASSAML engine exception
     */
    @Test
    public final void testValidateAuthnRequest() throws EIDASSAMLEngineException {
        final EIDASAuthnRequest validatedRequest = engine.validateEIDASAuthnRequest(getDefaultTestStorkAuthnRequestTokenSaml());

        assertEquals("CrossBorderShare incorrect: ", validatedRequest.isEIDCrossBorderShare(), false);
        assertEquals("CrossSectorShare incorrect: ", validatedRequest.isEIDCrossSectorShare(), false);
        assertEquals("SectorShare incorrect: ", validatedRequest.isEIDSectorShare(), false);

    }

    /**
     * Test validate data authenticate request. Verified parameters after
     * validation.
     *
     * @throws EIDASSAMLEngineException the EIDASSAML engine exception
     */
    @Test
    public final void testValidateDataAuthnRequest() throws EIDASSAMLEngineException {

        engine.setExtensionProcessor(new StorkExtensionProcessor());
        final EIDASAuthnRequest request = engine.validateEIDASAuthnRequest(getDefaultTestStorkAuthnRequestTokenSaml());

        assertEquals("Sestination incorrect: ", request.getDestination(), destination);

        assertEquals("CrossBorderShare incorrect: ", request.isEIDCrossBorderShare(), false);
        assertEquals("CrossSectorShare incorrect: ", request.isEIDCrossSectorShare(), false);
        assertEquals("SectorShare incorrect: ", request.isEIDSectorShare(), false);

        assertEquals("Service provider incorrect: ", request.getProviderName(), spName);
        assertEquals("QAAL incorrect: ", request.getQaa(), QAAL);
        assertEquals("SPSector incorrect: ", request.getSpSector(), spSector);
        assertEquals("SPInstitution incorrect: ", request.getSpInstitution(), null);
        assertEquals("SPApplication incorrect: ", request.getSpApplication(), spApplication);
        assertEquals("Asserition consumer URL incorrect: ", request.getAssertionConsumerServiceURL(), assertConsumerUrl);

        assertEquals("SP Country incorrect: ", request.getSpCountry(), spCountry);
        assertEquals("SP Id incorrect: ", request.getSPID(), spId);
        assertEquals("CitizenCountryCode incorrect: ", request.getCitizenCountryCode(), "ES");

    }

    /**
     * Test validate file authentication request. Validate from XML file.
     *
     * @throws Exception the exception
     */
    @Test
    public final void testValidateFileAuthnRequest() throws Exception {

        final byte[] bytes = SSETestUtils.readSamlFromFile("/data/eu/eidas/EIDASSAMLEngine/AuthnRequest.xml");

        try {
            engine.validateEIDASAuthnRequest(bytes);
            fail("testValidateFileAuthnRequest(...) should've thrown an EIDASSAMLEngineException!");
        } catch (EIDASSAMLEngineException e) {
            LOG.error(e.getMessage());
        }
    }

    /**
     * Test validate file authentication request tag delete.
     *
     * @throws Exception the exception
     */
    @Test
    public final void testValidateFileAuthnRequestTagDelete() throws Exception {

        final byte[] bytes = SSETestUtils.readSamlFromFile("/data/eu/eidas/EIDASSAMLEngine/AuthnRequestTagDelete.xml");

        try {
            engine.validateEIDASAuthnRequest(bytes);
            fail("validateEIDASAuthnRequest(...) should have thrown an EIDASSAMLEngineException!");
        } catch (EIDASSAMLEngineException e) {
            LOG.error(e.getMessage());

        }
    }

    /**
     * Test validate authentication request not trusted token.
     *
     * @throws EIDASSAMLEngineException the EIDASSAML engine exception
     */
    @Test
    public final void testValidateAuthnRequestNotTrustedErr1()
            throws EIDASSAMLEngineException {

        try {
            final EIDASSAMLEngine engineNotTrusted = EIDASSAMLEngine
                    .createSAMLEngine("CONF2");
            engineNotTrusted.setExtensionProcessor(new StorkExtensionProcessor());

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

            request.setSPID(spName);

            final byte[] authReqNotTrust = engineNotTrusted
                    .generateEIDASAuthnRequest(request).getTokenSaml();
            EIDASSAMLEngine engine=getEngine();
            engine.setExtensionProcessor(new StorkExtensionProcessor());
            engine.validateEIDASAuthnRequest(authReqNotTrust);
        } catch (EIDASSAMLEngineException e) {
            LOG.error("Error");
            fail("validateEIDASAuthnRequestNotTrusted(...) should not have thrown an EIDASSAMLEngineException!");
        }
    }

    /**
     * Test validate authentication request trusted.
     *
     * @throws EIDASSAMLEngineException the EIDASSAML engine exception
     */
    @Test
    public final void testValidateAuthnRequestTrusted()
            throws EIDASSAMLEngineException {

        final EIDASSAMLEngine engineTrusted = EIDASSAMLEngine
                .createSAMLEngine("CONF3");
        engineTrusted.setExtensionProcessor(new StorkExtensionProcessor());

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
        ///
        request.setSPID(spName);
        final byte[] authReqNotTrust = engineTrusted.generateEIDASAuthnRequest(
                request).getTokenSaml();

        // engine ("CONF1") no have trust certificate from "CONF2"
        final EIDASSAMLEngine engineNotTrusted = EIDASSAMLEngine.createSAMLEngine("CONF1");
        engineNotTrusted.setExtensionProcessor(new StorkExtensionProcessor());
        engineNotTrusted.validateEIDASAuthnRequest(authReqNotTrust);

    }


    /**
     * Test generate authentication request service provider application not null.
     */
    @Test
    public final void testGenerateAuthnRequestNADA() {
        final EIDASAuthnRequest request = new EIDASAuthnRequest();

        request.setDestination(destination);
        request.setProviderName(spName);
        request.setQaa(QAAL);
        request.setPersonalAttributeList(pal);
        request.setAssertionConsumerServiceURL(assertConsumerUrl);

        // news parameters
        request.setSpSector(null);
        request.setSpInstitution(null);
        request.setSpApplication(null);
        request.setSpCountry(null);
        request.setSPID("TEST_SP");

        try {
            authRequest = engine.generateEIDASAuthnRequest(request).getTokenSaml();
            engine.validateEIDASAuthnRequest(authRequest);
            assertNotNull(request.getSPID());
        } catch (EIDASSAMLEngineException e) {
            LOG.error("Error");
        }
    }

    /**
     * Test generate authentication request service provider application not null.
     */
    @Test
    public final void testGenerateAuthnRequestWithVIDPAuthenticationBlockAbsent() {
        final EIDASAuthnRequest request = new EIDASAuthnRequest();

        request.setDestination(destination);
        request.setProviderName(spName);
        request.setQaa(QAAL);
        request.setPersonalAttributeList(pal);
        request.setAssertionConsumerServiceURL(assertConsumerUrl);

        // news parameters
        request.setSpSector(null);
        request.setSpInstitution(null);
        request.setSpApplication(null);
        request.setSpCountry(null);

        try {
            authRequest = engine.generateEIDASAuthnRequest(request).getTokenSaml();
            engine.validateEIDASAuthnRequest(authRequest);
            assertNull(request.getSPID());
        } catch (EIDASSAMLEngineException e) {
            LOG.error("Error");
        }
    }

    /**
     * Test validate authentication request with unknown elements.
     *
     * @throws EIDASSAMLEngineException the EIDASSAML engine exception
     */
    @Test
    public final void testValidateAuthnRequestWithUnknownElements() throws EIDASSAMLEngineException {

        final EIDASAuthnRequest request = new EIDASAuthnRequest();

        request.setDestination(destination);
        request.setProviderName(spName);
        request.setQaa(QAAL);
        request.setPersonalAttributeList(pal);
        request.setAssertionConsumerServiceURL(assertConsumerUrl);

        IPersonalAttributeList pAttList = new PersonalAttributeList();

        final PersonalAttribute unknown = new PersonalAttribute();
        unknown.setName("unknown");
        unknown.setIsRequired(true);
        pAttList.add(unknown);

        final PersonalAttribute eIdentifier = new PersonalAttribute();
        eIdentifier.setName("eIdentifier");
        eIdentifier.setIsRequired(true);
        pAttList.add(eIdentifier);

        request.setPersonalAttributeList(pAttList);

        // new parameters
        request.setSpSector(spSector);
        request.setSpInstitution(spInstitution);
        request.setSpApplication(spApplication);
        request.setSpCountry(spCountry);
        request.setSPID(spId);
        request.setCitizenCountryCode("ES");
        request.setMessageFormatName(SAMLExtensionFormat.STORK1_FORMAT_NAME);

        EIDASAuthnRequest req = new EIDASAuthnRequest();

        req = engine3.generateEIDASAuthnRequest(request);

        byte[] tokenSaml=req.getTokenSaml();
        String s=new String(tokenSaml, Charset.forName("UTF-8"));
        req = engine.validateEIDASAuthnRequest(tokenSaml);

        assertNull("The value shouldn't exist", req.getPersonalAttributeList().get("unknown"));
        assertNotNull("The value should exist", req.getPersonalAttributeList().get("eIdentifier"));

    }

    /**
     * Test generate Request with required elements by default
     *
     * @throws EIDASSAMLEngineException the EIDASSAML engine exception
     */
    @Test
    public final void testGenerateAuthnRequestWithIsRequiredElementsByDefault() throws EIDASSAMLEngineException {

        final EIDASAuthnRequest request = new EIDASAuthnRequest();

        request.setDestination(destination);
        request.setProviderName(spName);
        request.setQaa(QAAL);
        request.setPersonalAttributeList(pal);
        request.setAssertionConsumerServiceURL(assertConsumerUrl);

        IPersonalAttributeList pAttList = new PersonalAttributeList();

        final PersonalAttribute eIdentifier = new PersonalAttribute();
        eIdentifier.setName("eIdentifier");
        eIdentifier.setIsRequired(true);
        pAttList.add(eIdentifier);

        request.setPersonalAttributeList(pAttList);

        // new parameters
        request.setSpSector(spSector);
        request.setSpInstitution(spInstitution);
        request.setSpApplication(spApplication);
        request.setSpCountry(spCountry);
        request.setSPID(spId);
        request.setCitizenCountryCode("ES");

        EIDASAuthnRequest req = new EIDASAuthnRequest();
        EIDASAuthnRequest reqTrue = new EIDASAuthnRequest();
        EIDASAuthnRequest reqFalse = new EIDASAuthnRequest();

        reqTrue = engine.generateEIDASAuthnRequest(request);
        reqFalse = engine2.generateEIDASAuthnRequest(request);
        req = engine3.generateEIDASAuthnRequest(request);


        String token = new String(req.getTokenSaml());
        String reqTrueToken = new String(reqTrue.getTokenSaml());
        String reqFalseToken = new String(reqFalse.getTokenSaml());

        assertTrue("The token must contain the chain 'isRequired'", token.contains("isRequired"));
        assertTrue("The token must contain the chain 'isRequired'", reqTrueToken.contains("isRequired"));
        assertFalse("The token must contain the chain 'isRequired'", reqFalseToken.contains("isRequired"));

    }

    /**
     * Test validating request and getting alias used to save
     * the saml trusted certificate into trustore
     *
     * @throws EIDASSAMLEngineException the EIDASSAML engine exception
     */
    @Test
    public final void testValidateAuthnRequestGettingItsAlias() throws EIDASSAMLEngineException {

        final EIDASAuthnRequest request = new EIDASAuthnRequest();

        request.setDestination(destination);
        request.setProviderName(spName);
        request.setQaa(QAAL);
        request.setPersonalAttributeList(pal);
        request.setAssertionConsumerServiceURL(assertConsumerUrl);

        IPersonalAttributeList pAttList = new PersonalAttributeList();

        final PersonalAttribute eIdentifier = new PersonalAttribute();
        eIdentifier.setName("eIdentifier");
        eIdentifier.setIsRequired(true);
        pAttList.add(eIdentifier);

        request.setPersonalAttributeList(pAttList);

        // new parameters
        request.setSpSector(spSector);
        request.setSpInstitution(spInstitution);
        request.setSpApplication(spApplication);
        request.setSpCountry(spCountry);
        request.setSPID(spId);
        request.setCitizenCountryCode("ES");

        EIDASAuthnRequest req = new EIDASAuthnRequest();
        EIDASSAMLEngine engine=getEngine();
        engine.setExtensionProcessor(new StorkExtensionProcessor());
        EIDASSAMLEngine engine3=getEngine3();
        engine3.setExtensionProcessor(new StorkExtensionProcessor());
        EIDASSAMLEngine engine2=getEngine2();
        engine2.setExtensionProcessor(new StorkExtensionProcessor());
        req = engine3.generateEIDASAuthnRequest(request);
        req = engine.validateEIDASAuthnRequest(req.getTokenSaml());
        assertTrue("The alias should match this value", req.getAlias().equals("local-demo-cert"));

        req = engine2.generateEIDASAuthnRequest(request);
        req = engine2.validateEIDASAuthnRequest(req.getTokenSaml());
        assertTrue("The alias should match this value", req.getAlias().equals("local-demo-cert"));


    }

    /**
     * Test generating/validating request with signedDoc
     *
     * @throws EIDASSAMLEngineException the EIDASSAML engine exception
     */
    @Test
    public final void testGenerateAuthnRequestWithSignedDoc()
            throws EIDASSAMLEngineException {

        String signedDocRequest = "<dss:SignRequest xmlns:dss=\"urn:oasis:names:tc:dss:1.0:core:schema\" RequestID=\"_d96b62a87d18f1095170c1f44c90b5fd\"><dss:InputDocuments><dss:Document><dss:Base64Data MimeType=\"text/plain\">VGVzdCB0ZXh0</dss:Base64Data></dss:Document></dss:InputDocuments></dss:SignRequest>";

        final EIDASAuthnRequest request = new EIDASAuthnRequest();

        PersonalAttributeList paler = new PersonalAttributeList();

        final PersonalAttribute eIDNumber = new PersonalAttribute();
        eIDNumber.setName("eIdentifier");
        eIDNumber.setIsRequired(true);
        paler.add(eIDNumber);

        final PersonalAttribute isAgeOver = new PersonalAttribute();
        isAgeOver.setName("isAgeOver");
        isAgeOver.setIsRequired(true);
        final ArrayList<String> ages = new ArrayList<String>();
        ages.add("16");
        ages.add("18");
        isAgeOver.setValue(ages);
        paler.add(isAgeOver);

        final PersonalAttribute signedDoc = new PersonalAttribute();
        signedDoc.setName("signedDoc");
        final ArrayList<String> signedDocs = new ArrayList<String>();
        signedDocs.add(signedDocRequest);
        signedDoc.setValue(signedDocs);
        signedDoc.setIsRequired(false);
        paler.add(signedDoc);

        request.setDestination(destination);
        request.setProviderName(spName);
        request.setQaa(QAAL);
        request.setPersonalAttributeList(paler);
        request.setAssertionConsumerServiceURL(assertConsumerUrl);

        // new parameters
        request.setSpSector(spSector);
        request.setSpInstitution(spInstitution);
        request.setSpApplication(spApplication);
        request.setSpCountry(spCountry);
        request.setSPID(spId);
        request.setCitizenCountryCode("ES");

        EIDASAuthnRequest req = new EIDASAuthnRequest();

        req = engine.generateEIDASAuthnRequest(request);
        String asXml=new String(req.getTokenSaml(), Charset.forName("UTF-8"));
        req = engine.validateEIDASAuthnRequest(req.getTokenSaml());

        assertTrue("SignedDoc request should be the same: "+asXml, req
                .getPersonalAttributeList().get("signedDoc").getValue().get(0)
                .equals(signedDocRequest));


    }

    /**
     * Return the default EIDAS authRequest token used in the tests.
     * @return default EIDAS authRequest token
     * @throws EIDASSAMLEngineException
     */
    private final byte[] getDefaultTestStorkAuthnRequestTokenSaml() throws EIDASSAMLEngineException {
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

        return engine.generateEIDASAuthnRequest(request).getTokenSaml();
    }

}
