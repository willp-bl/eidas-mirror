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

package eu.stork.peps.test.simple;

import static org.junit.Assert.*;

import java.nio.charset.Charset;
import java.util.ArrayList;

import eu.stork.peps.auth.engine.core.stork.StorkExtensionProcessor;
import org.junit.Test;

import org.opensaml.xml.parse.BasicParserPool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.stork.peps.auth.commons.IPersonalAttributeList;
import eu.stork.peps.auth.commons.PersonalAttribute;
import eu.stork.peps.auth.commons.PersonalAttributeList;
import eu.stork.peps.auth.commons.STORKAuthnRequest;
import eu.stork.peps.auth.engine.STORKSAMLEngine;
import eu.stork.peps.exceptions.STORKSAMLEngineException;

/**
 * The Class StorkAuthRequestTest defines a class to .
 */
public class StorkAuthRequestTest {

    /**
     * The engines.
     */
    private static STORKSAMLEngine engine = null;

    private static STORKSAMLEngine engine2 = null;
    private static STORKSAMLEngine engine3 = null;
    static{
        try{
            engine=STORKSAMLEngine.createSTORKSAMLEngine("CONF1");
            engine.setExtensionProcessor(new StorkExtensionProcessor());
            engine2 = STORKSAMLEngine.createSTORKSAMLEngine("CONF2");
            engine2.setExtensionProcessor(new StorkExtensionProcessor());
            engine3 = STORKSAMLEngine.createSTORKSAMLEngine("CONF3");
            engine3.setExtensionProcessor(new StorkExtensionProcessor());
        }catch(STORKSAMLEngineException exc){
            fail("Failed to initialize SAMLEngines");
        }
    }

    private STORKSAMLEngine getEngine(){
        return helperGetEngine("CONF1");
    }

    private STORKSAMLEngine getEngine2(){
        return helperGetEngine("CONF2");
    }

    private STORKSAMLEngine getEngine3(){
        return helperGetEngine("CONF3");
    }

    private STORKSAMLEngine helperGetEngine(String name){
        STORKSAMLEngine engine = null;
        try {
            engine = STORKSAMLEngine.createSTORKSAMLEngine(name);
            engine.setExtensionProcessor(new StorkExtensionProcessor());
        }catch(STORKSAMLEngineException exc){
            fail("Failed to initialize SAMLEngines");
        }
        return engine;

    }

    /**
     * Instantiates a new stork authentication request test.
     */
    public StorkAuthRequestTest() {
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

        destination = "http://C-PEPS.gov.xx/PEPS/ColleagueRequest";
        assertConsumerUrl = "http://S-PEPS.gov.xx/PEPS/ColleagueResponse";

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
            .getLogger(StorkAuthRequestTest.class.getName());

    /**
     * Parser manager used to parse XML.
     */
    private static BasicParserPool parser;

    static {
        parser = STORKSAMLEngine.getNewBasicSecuredParserPool();
    }

    /**
     * Test generate authentication request.
     *
     * @throws STORKSAMLEngineException the STORKSAML engine exception
     */
    @Test
    public final void testGenerateAuthnRequest() throws STORKSAMLEngineException {

        final STORKAuthnRequest request = new STORKAuthnRequest();

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

        //engine.generateSTORKAuthnRequest(request);

        LOG.info("STORKAuthnRequest 1: " + SSETestUtils.encodeSAMLToken(engine.generateSTORKAuthnRequest(request).getTokenSaml()));
        request.setCitizenCountryCode("ES");
        LOG.info("STORKAuthnRequest 2: " + SSETestUtils.encodeSAMLToken(engine.generateSTORKAuthnRequest(request).getTokenSaml()));
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

        final STORKAuthnRequest request = new STORKAuthnRequest();

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
            engine.generateSTORKAuthnRequest(request);
            fail("generateSTORKAuthnRequest(...) should've thrown an STORKSAMLEngineException!");
        } catch (STORKSAMLEngineException e) {
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


        final STORKAuthnRequest request = new STORKAuthnRequest();

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
            engine.generateSTORKAuthnRequest(request);
            fail("generateSTORKAuthnRequest(...) should've thrown an STORKSAMLEngineException!");
        } catch (STORKSAMLEngineException e) {
            LOG.error("Error");
        }
    }

    /**
     * Test generate authentication request error provider name null.
     */
    @Test
    public final void testGenerateAuthnRequestSPNAmeErr1() {


        final STORKAuthnRequest request = new STORKAuthnRequest();

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
            engine.generateSTORKAuthnRequest(request);
            fail("generateSTORKAuthnRequest(...) should've thrown an STORKSAMLEngineException!");
        } catch (STORKSAMLEngineException e) {
            LOG.error("Error");
        }
    }

    /**
     * Test generate authentication request authentication assurance level
     * negative value.
     */
    @Test
    public final void testGenerateAuthnRequestQaalErr1() {

        final STORKAuthnRequest request = new STORKAuthnRequest();

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
            engine.generateSTORKAuthnRequest(request);
            fail("generateSTORKAuthnRequest(...) should've thrown an STORKSAMLEngineException!");
        } catch (STORKSAMLEngineException e) {
            LOG.error("Error");
        }
    }

    /**
     * Test generate authentication request service provider sector null.
     */
    @Test
    public final void testGenerateAuthnRequestSectorErr() {

        final STORKAuthnRequest request = new STORKAuthnRequest();

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
            engine.generateSTORKAuthnRequest(request);
        } catch (STORKSAMLEngineException e) {
            LOG.error("Error");
            fail("generateSTORKAuthnRequest(...) should've thrown an STORKSAMLEngineException!");

        }
    }

    /**
     * Test generate authentication request service provider institution null.
     */
    @Test
    public final void testGenerateAuthnRequestInstitutionrErr() {

        final STORKAuthnRequest request = new STORKAuthnRequest();

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
            engine.generateSTORKAuthnRequest(request);

        } catch (STORKSAMLEngineException e) {
            LOG.error("Error");
            fail("generateSTORKAuthnRequest(...) should've thrown an STORKSAMLEngineException!");
        }
    }

    /**
     * Test generate authentication request service provider application null.
     */
    @Test
    public final void testGenerateAuthnRequestApplicationErr() {

        final STORKAuthnRequest request = new STORKAuthnRequest();

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
            engine.generateSTORKAuthnRequest(request);

        } catch (STORKSAMLEngineException e) {
            LOG.error("Error");
            fail("generateSTORKAuthnRequest(...) should've thrown an STORKSAMLEngineException!");
        }
    }

    /**
     * Test generate authentication request service provider country null.
     */
    @Test
    public final void testGenerateAuthnRequestCountryErr() {

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
        request.setSpCountry(null);
        request.setSPID(spId);
        request.setCitizenCountryCode("ES");

        try {
            engine.generateSTORKAuthnRequest(request);

        } catch (STORKSAMLEngineException e) {
            LOG.error("Error");
            fail("generateSTORKAuthnRequest(...) should've thrown an STORKSAMLEngineException!");
        }
    }

    /**
     * Test generate authentication request error with quality authentication
     * assurance level wrong.
     */
    @Test
    public final void testGenerateAuthnRequestQaalErr2() {
        final STORKAuthnRequest request = new STORKAuthnRequest();

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
            engine.generateSTORKAuthnRequest(request);
            fail("generateSTORKAuthnRequest(...) should've thrown an STORKSAMLEngineException!");
        } catch (STORKSAMLEngineException e) {
            LOG.error("Error");
        }
    }

    /**
     * Test generate authentication request personal attribute list null value.
     */
    @Test
    public final void testGenerateAuthnRequestPALErr1() {
        final STORKAuthnRequest request = new STORKAuthnRequest();

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
            engine.generateSTORKAuthnRequest(request);
            fail("generateSTORKAuthnRequest(...) should've thrown an STORKSAMLEngineException!");
        } catch (STORKSAMLEngineException e) {
            LOG.error("Error");
        }
    }

    /**
     * Test generate authentication request error with assertion consumer URL
     * null.
     */
    @Test
    public final void testGenerateAuthnRequestAssertionConsumerErr1() {
        final STORKAuthnRequest request = new STORKAuthnRequest();

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
            engine.generateSTORKAuthnRequest(request);
            fail("generateSTORKAuthnRequest(...) should've thrown an STORKSAMLEngineException!");
        } catch (STORKSAMLEngineException e) {
            LOG.error("Error");
        }
    }

    /**
     * Test validate authentication request null parameter.
     *
     * @throws STORKSAMLEngineException the STORKSAML engine exception
     */
    @Test
    public final void testValidateAuthnRequestNullParam()
            throws STORKSAMLEngineException {
        try {
            engine.validateSTORKAuthnRequest(null);
            fail("validateSTORKAuthnRequest(...) should've thrown an STORKSAMLEngineException!");
        } catch (STORKSAMLEngineException e) {
            LOG.error("Error");
        }
    }

    /**
     * Test validate authentication request error bytes encode.
     *
     * @throws STORKSAMLEngineException the STORKSAML engine exception
     */
    @Test
    public final void testValidateAuthnRequestErrorEncode()
            throws STORKSAMLEngineException {
        try {
            engine.validateSTORKAuthnRequest("messageError".getBytes());
            fail("validateSTORKAuthnRequest(...) should've thrown an STORKSAMLEngineException!");
        } catch (STORKSAMLEngineException e) {
            LOG.error("Error");
        }
    }

    /**
     * Test validate authentication request.
     *
     * @throws STORKSAMLEngineException the STORKSAML engine exception
     */
    @Test
    public final void testValidateAuthnRequest() throws STORKSAMLEngineException {
        final STORKAuthnRequest validatedRequest = engine.validateSTORKAuthnRequest(getDefaultTestStorkAuthnRequestTokenSaml());

        assertEquals("CrossBorderShare incorrect: ", validatedRequest.isEIDCrossBorderShare(), false);
        assertEquals("CrossSectorShare incorrect: ", validatedRequest.isEIDCrossSectorShare(), false);
        assertEquals("SectorShare incorrect: ", validatedRequest.isEIDSectorShare(), false);

    }

    /**
     * Test validate data authenticate request. Verified parameters after
     * validation.
     *
     * @throws STORKSAMLEngineException the STORKSAML engine exception
     */
    @Test
    public final void testValidateDataAuthnRequest() throws STORKSAMLEngineException {

        engine.setExtensionProcessor(new StorkExtensionProcessor());
        final STORKAuthnRequest request = engine.validateSTORKAuthnRequest(getDefaultTestStorkAuthnRequestTokenSaml());

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

        final byte[] bytes = SSETestUtils.readStorkSamlFromFile("/data/eu/stork/STORKSAMLEngine/AuthnRequest.xml");

        try {
            engine.validateSTORKAuthnRequest(bytes);
            fail("testValidateFileAuthnRequest(...) should've thrown an STORKSAMLEngineException!");
        } catch (STORKSAMLEngineException e) {
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

        final byte[] bytes = SSETestUtils.readStorkSamlFromFile("/data/eu/stork/STORKSAMLEngine/AuthnRequestTagDelete.xml");

        try {
            engine.validateSTORKAuthnRequest(bytes);
            fail("validateSTORKAuthnRequest(...) should have thrown an STORKSAMLEngineException!");
        } catch (STORKSAMLEngineException e) {
            LOG.error(e.getMessage());

        }
    }

    /**
     * Test validate authentication request not trusted token.
     *
     * @throws STORKSAMLEngineException the STORKSAML engine exception
     */
    @Test
    public final void testValidateAuthnRequestNotTrustedErr1()
            throws STORKSAMLEngineException {

        try {
            final STORKSAMLEngine engineNotTrusted = STORKSAMLEngine
                    .createSTORKSAMLEngine("CONF2");
            engineNotTrusted.setExtensionProcessor(new StorkExtensionProcessor());

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

            request.setSPID(spName);

            final byte[] authReqNotTrust = engineNotTrusted
                    .generateSTORKAuthnRequest(request).getTokenSaml();
            STORKSAMLEngine engine=getEngine();
            engine.setExtensionProcessor(new StorkExtensionProcessor());
            engine.validateSTORKAuthnRequest(authReqNotTrust);
        } catch (STORKSAMLEngineException e) {
            LOG.error("Error");
            fail("validateSTORKAuthnRequestNotTrusted(...) should not have thrown an STORKSAMLEngineException!");
        }
    }

    /**
     * Test validate authentication request trusted.
     *
     * @throws STORKSAMLEngineException the STORKSAML engine exception
     */
    @Test
    public final void testValidateAuthnRequestTrusted()
            throws STORKSAMLEngineException {

        final STORKSAMLEngine engineTrusted = STORKSAMLEngine
                .createSTORKSAMLEngine("CONF3");
        engineTrusted.setExtensionProcessor(new StorkExtensionProcessor());

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
        ///
        request.setSPID(spName);
        final byte[] authReqNotTrust = engineTrusted.generateSTORKAuthnRequest(
                request).getTokenSaml();

        // engine ("CONF1") no have trust certificate from "CONF2"
        final STORKSAMLEngine engineNotTrusted = STORKSAMLEngine.createSTORKSAMLEngine("CONF1");
        engineNotTrusted.setExtensionProcessor(new StorkExtensionProcessor());
        engineNotTrusted.validateSTORKAuthnRequest(authReqNotTrust);

    }


    /**
     * Test generate authentication request service provider application not null.
     */
    @Test
    public final void testGenerateAuthnRequestNADA() {
        final STORKAuthnRequest request = new STORKAuthnRequest();

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
            authRequest = engine.generateSTORKAuthnRequest(request).getTokenSaml();
            engine.validateSTORKAuthnRequest(authRequest);
            assertNotNull(request.getSPID());
        } catch (STORKSAMLEngineException e) {
            LOG.error("Error");
        }
    }

    /**
     * Test generate authentication request service provider application not null.
     */
    @Test
    public final void testGenerateAuthnRequestWithVIDPAuthenticationBlockAbsent() {
        final STORKAuthnRequest request = new STORKAuthnRequest();

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
            authRequest = engine.generateSTORKAuthnRequest(request).getTokenSaml();
            engine.validateSTORKAuthnRequest(authRequest);
            assertNull(request.getSPID());
        } catch (STORKSAMLEngineException e) {
            LOG.error("Error");
        }
    }

    /**
     * Test validate authentication request with unknown elements.
     *
     * @throws STORKSAMLEngineException the STORKSAML engine exception
     */
    @Test
    public final void testValidateAuthnRequestWithUnknownElements() throws STORKSAMLEngineException {

        final STORKAuthnRequest request = new STORKAuthnRequest();

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

        STORKAuthnRequest req = new STORKAuthnRequest();

        req = engine3.generateSTORKAuthnRequest(request);

        req = engine.validateSTORKAuthnRequest(req.getTokenSaml());

        assertNull("The value shouldn't exist", req.getPersonalAttributeList().get("unknown"));
        assertNotNull("The value should exist", req.getPersonalAttributeList().get("eIdentifier"));

    }

    /**
     * Test generate Request with required elements by default
     *
     * @throws STORKSAMLEngineException the STORKSAML engine exception
     */
    @Test
    public final void testGenerateAuthnRequestWithIsRequiredElementsByDefault() throws STORKSAMLEngineException {

        final STORKAuthnRequest request = new STORKAuthnRequest();

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

        STORKAuthnRequest req = new STORKAuthnRequest();
        STORKAuthnRequest reqTrue = new STORKAuthnRequest();
        STORKAuthnRequest reqFalse = new STORKAuthnRequest();

        reqTrue = engine.generateSTORKAuthnRequest(request);
        reqFalse = engine2.generateSTORKAuthnRequest(request);
        req = engine3.generateSTORKAuthnRequest(request);


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
     * @throws STORKSAMLEngineException the STORKSAML engine exception
     */
    @Test
    public final void testValidateAuthnRequestGettingItsAlias() throws STORKSAMLEngineException {

        final STORKAuthnRequest request = new STORKAuthnRequest();

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

        STORKAuthnRequest req = new STORKAuthnRequest();
        STORKSAMLEngine engine=getEngine();
        engine.setExtensionProcessor(new StorkExtensionProcessor());
        STORKSAMLEngine engine3=getEngine3();
        engine3.setExtensionProcessor(new StorkExtensionProcessor());
        STORKSAMLEngine engine2=getEngine2();
        engine2.setExtensionProcessor(new StorkExtensionProcessor());
        req = engine3.generateSTORKAuthnRequest(request);
        req = engine.validateSTORKAuthnRequest(req.getTokenSaml());
        assertTrue("The alias should match this value", req.getAlias().equals("local-demo-cert"));

        req = engine2.generateSTORKAuthnRequest(request);
        req = engine2.validateSTORKAuthnRequest(req.getTokenSaml());
        assertTrue("The alias should match this value", req.getAlias().equals("local-demo-cert"));


    }

    /**
     * Test generating/validating request with signedDoc
     *
     * @throws STORKSAMLEngineException the STORKSAML engine exception
     */
    @Test
    public final void testGenerateAuthnRequestWithSignedDoc()
            throws STORKSAMLEngineException {

        String signedDocRequest = "<dss:SignRequest xmlns:dss=\"urn:oasis:names:tc:dss:1.0:core:schema\" RequestID=\"_d96b62a87d18f1095170c1f44c90b5fd\"><dss:InputDocuments><dss:Document><dss:Base64Data MimeType=\"text/plain\">VGVzdCB0ZXh0</dss:Base64Data></dss:Document></dss:InputDocuments></dss:SignRequest>";

        final STORKAuthnRequest request = new STORKAuthnRequest();

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

        STORKAuthnRequest req = new STORKAuthnRequest();

        req = engine.generateSTORKAuthnRequest(request);
        String asXml=new String(req.getTokenSaml(), Charset.forName("UTF-8"));
        req = engine.validateSTORKAuthnRequest(req.getTokenSaml());

        assertTrue("SignedDoc request should be the same: "+asXml, req
                .getPersonalAttributeList().get("signedDoc").getValue().get(0)
                .equals(signedDocRequest));


    }

    /**
     * Return the default Stork authRequest token used in the tests.
     * @return default Stork authRequest token
     * @throws STORKSAMLEngineException
     */
    private final byte[] getDefaultTestStorkAuthnRequestTokenSaml() throws STORKSAMLEngineException {
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

        return engine.generateSTORKAuthnRequest(request).getTokenSaml();
    }

}
