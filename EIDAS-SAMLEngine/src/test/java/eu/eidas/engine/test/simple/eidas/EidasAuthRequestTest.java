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

package eu.eidas.engine.test.simple.eidas;

import eu.eidas.auth.commons.*;
import eu.eidas.auth.engine.EIDASSAMLEngine;
import eu.eidas.auth.engine.core.SAMLCore;
import eu.eidas.auth.engine.core.SAMLExtensionFormat;
import eu.eidas.auth.engine.core.eidas.EidasExtensionProcessor;
import eu.eidas.auth.engine.core.stork.StorkExtensionProcessor;
import eu.eidas.engine.exceptions.EIDASSAMLEngineException;
import eu.eidas.engine.test.simple.SSETestUtils;

import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.opensaml.xml.parse.BasicParserPool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.util.ArrayList;

import static org.junit.Assert.*;

/**
 * The Class EidasAuthRequestTest performs unit test for EIDAS format requests
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EidasAuthRequestTest {

	private static final String NAMEID_FORMAT="urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
	private static final String LOA_LOW="http://eidas.europa.eu/LoA/low";
    /**
     * The engines.
     */
    EIDASSAMLEngine getEngine(){
        return getEngine("CONF1");
    }
    EIDASSAMLEngine getEngine2(){
        return getEngine("CONF2");
    }
    EIDASSAMLEngine getEngine3(){
        return getEngine("CONF3");
    }
    EIDASSAMLEngine getEngine4(){
        return getEngine("CONF4");
    }
    EIDASSAMLEngine getEngine(String conf) {
        EIDASSAMLEngine engine = null;
        try {
            engine = EIDASSAMLEngine.createSAMLEngine(conf);
            engine.setExtensionProcessor(new EidasExtensionProcessor());
        } catch (EIDASSAMLEngineException exc) {
            fail("Failed to initialize SAMLEngines");
        }
        return engine;
    }

    /**
     * Instantiates a new authentication request test.
     */
    public EidasAuthRequestTest() {
        pal = new PersonalAttributeList();

        final PersonalAttribute dateOfBirth = new PersonalAttribute();
        dateOfBirth.setName("DateOfBirth");
        dateOfBirth.setIsRequired(false);
        pal.add(dateOfBirth);

        final PersonalAttribute eIDNumber = new PersonalAttribute();
        eIDNumber.setName("PersonIdentifier");
        eIDNumber.setIsRequired(true);
        pal.add(eIDNumber);

        final PersonalAttribute familyName = new PersonalAttribute();
        familyName.setName("FamilyName");
        familyName.setIsRequired(true);
        pal.add(familyName);

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
        request.setMessageFormatName(SAMLExtensionFormat.EIDAS10.getName());

        // new parameters
        request.setCitizenCountryCode("ES");
        request.setSPType("public");
        request.setEidasLoA(LOA_LOW);
        request.setEidasNameidFormat(NAMEID_FORMAT);
        final IPersonalAttributeList attrList = new PersonalAttributeList();

        final PersonalAttribute newAttr = new PersonalAttribute();
        newAttr.setName("EidasAdditionalAttribute");
        newAttr.setIsRequired(true);
        attrList.add(newAttr);
        request.setPersonalAttributeList(attrList);

        byte [] samlToken = getEngine().generateEIDASAuthnRequest(request).getTokenSaml();
        LOG.info("EIDASAuthnRequest 1: " + SSETestUtils.encodeSAMLToken(samlToken));
        EIDASAuthnRequest parsedRequest = getEngine().validateEIDASAuthnRequest(samlToken);
        assertNotNull(parsedRequest);
        assertFalse(parsedRequest.getPersonalAttributeList().isEmpty());
        request.setCitizenCountryCode("ES");
        LOG.info("EIDASAuthnRequest 2: " + SSETestUtils.encodeSAMLToken(getEngine().generateEIDASAuthnRequest(request).getTokenSaml()));
    }


    /**
     * Test generate authentication request error personal attribute name error.
     */
    @Test
    public final void testGenerateAuthnRequestPALsErr1() {

        final IPersonalAttributeList palWrong = new PersonalAttributeList();

        final PersonalAttribute wrongAttr = new PersonalAttribute();
        wrongAttr.setName("attrNotValid");
        wrongAttr.setIsRequired(true);

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
            getEngine().generateEIDASAuthnRequest(request);
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
            getEngine().generateEIDASAuthnRequest(request);
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
            getEngine().generateEIDASAuthnRequest(request);
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
            getEngine().generateEIDASAuthnRequest(request);
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
            getEngine().generateEIDASAuthnRequest(request);

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
            getEngine().generateEIDASAuthnRequest(request);

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
            getEngine().generateEIDASAuthnRequest(request);

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
    public final void testGenerateAuthnRequestLoAErr() {
        final EIDASAuthnRequest request = new EIDASAuthnRequest();

        request.setDestination(destination);
        request.setProviderName(spName);
        request.setQaa(0);
        request.setPersonalAttributeList(pal);
        request.setEidasLoA("incorrectvalue");

        // news parameters
        request.setSpSector(spSector);
        request.setSpInstitution(spInstitution);
        request.setSpApplication(spApplication);
        request.setSpCountry(spCountry);
        request.setSPID(spId);
        request.setCitizenCountryCode("ES");

        try {
            getEngine().generateEIDASAuthnRequest(request);
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
            getEngine().generateEIDASAuthnRequest(request);
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
            getEngine().validateEIDASAuthnRequest(null);
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
            getEngine().validateEIDASAuthnRequest("messageError".getBytes());
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
        final EIDASAuthnRequest validatedRequest = getEngine().validateEIDASAuthnRequest(getDefaultTestStorkAuthnRequestTokenSaml());

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

        final EIDASAuthnRequest request = getEngine().validateEIDASAuthnRequest(getDefaultTestStorkAuthnRequestTokenSaml());

        assertEquals("Sestination incorrect: ", request.getDestination(), destination);

//        assertEquals("CrossBorderShare incorrect: ", request.isEIDCrossBorderShare(), false);
//        assertEquals("CrossSectorShare incorrect: ", request.isEIDCrossSectorShare(), false);
//        assertEquals("SectorShare incorrect: ", request.isEIDSectorShare(), false);

        assertEquals("Service provider incorrect: ", request.getProviderName(), spName);
//        assertEquals("QAAL incorrect: ", request.getQaa(), QAAL);
//        assertEquals("SPInstitution incorrect: ", request.getSpInstitution(), null);
//        assertEquals("SPApplication incorrect: ", request.getSpApplication(), spApplication);
        assertEquals("Asserition consumer URL incorrect: ", request.getAssertionConsumerServiceURL(), assertConsumerUrl);

//        assertEquals("SP Country incorrect: ", request.getSpCountry(), spCountry);
//        assertEquals("SP Id incorrect: ", request.getSPID(), spId);
//        assertEquals("CitizenCountryCode incorrect: ", request.getCitizenCountryCode(), "ES");

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
            getEngine().validateEIDASAuthnRequest(bytes);
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
            getEngine().validateEIDASAuthnRequest(bytes);
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
            engineNotTrusted.setExtensionProcessor(new EidasExtensionProcessor());

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
            request.setSPType("public");

            request.setSPID(spName);
            request.setEidasLoA(LOA_LOW);
            request.setEidasNameidFormat(NAMEID_FORMAT);

            final byte[] authReqNotTrust = engineNotTrusted
                    .generateEIDASAuthnRequest(request).getTokenSaml();

            getEngine().validateEIDASAuthnRequest(authReqNotTrust);
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
        engineTrusted.setExtensionProcessor(new EidasExtensionProcessor());

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
        request.setSPType("public");
        ///
        request.setSPID(spName);
        request.setEidasLoA(LOA_LOW);
        request.setEidasNameidFormat(NAMEID_FORMAT);
        final byte[] authReqNotTrust = engineTrusted.generateEIDASAuthnRequest(
                request).getTokenSaml();

        // engine ("CONF1") no have trust certificate from "CONF2"
        getEngine().validateEIDASAuthnRequest(authReqNotTrust);

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
            authRequest = getEngine().generateEIDASAuthnRequest(request).getTokenSaml();
            getEngine().validateEIDASAuthnRequest(authRequest);
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
            authRequest = getEngine().generateEIDASAuthnRequest(request).getTokenSaml();
            getEngine().validateEIDASAuthnRequest(authRequest);
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
        eIdentifier.setName("PersonIdentifier");
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
        request.setSPType("public");
        request.setEidasLoA(LOA_LOW);
        request.setEidasNameidFormat(NAMEID_FORMAT);

        EIDASAuthnRequest req = getEngine3().generateEIDASAuthnRequest(request);
        String saml=new String(req.getTokenSaml(), Charset.forName("UTF-8"));
        assertFalse(saml.isEmpty());

        req = getEngine().validateEIDASAuthnRequest(req.getTokenSaml());

        assertNull("The value shouldn't exist", req.getPersonalAttributeList().get("unknown"));
        assertNotNull("The value should exist", req.getPersonalAttributeList().get("PersonIdentifier"));

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

        reqTrue = getEngine().generateEIDASAuthnRequest(request);
        reqFalse = getEngine2().generateEIDASAuthnRequest(request);
        req = getEngine3().generateEIDASAuthnRequest(request);


        String token = new String(req.getTokenSaml());
        String reqTrueToken = new String(reqTrue.getTokenSaml());
        String reqFalseToken = new String(reqFalse.getTokenSaml());

        assertTrue("The token must contain the chain 'isRequired'", token.contains("isRequired"));
        assertTrue("The token must contain the chain 'isRequired'", reqTrueToken.contains("isRequired"));
        assertFalse("The token must contain the chain 'isRequired'", reqFalseToken.contains("isRequired"));

    }



    /**
     * Test cross validation: a request in EIDAS format validated against an eidas engine
     *
     * @throws EIDASSAMLEngineException the EIDASSAML engine exception
     */
    @Test
    public final void testCrossValidation()
            throws EIDASSAMLEngineException {

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

        //prepare request in STORK format
        EIDASSAMLEngine storkEngine = getEngine4();
        storkEngine.setExtensionProcessor(new StorkExtensionProcessor());
        req = storkEngine.generateEIDASAuthnRequest(request);
        String asXml=new String(req.getTokenSaml(), Charset.forName("UTF-8"));

        //validate request in a EIDAS enabled samlengine
        try {
            req = getEngine().validateEIDASAuthnRequest(req.getTokenSaml());
            assertTrue("should throw a validation exception", false);
        }catch(EIDASSAMLEngineException exc){

        }

    }



    /**
     * Return the default authRequest token used in the tests.
     * @return default authRequest token
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
        request.setSPType("public");
        request.setEidasLoA("http://eidas.europa.eu/LoA/low");
        request.setMessageFormatName(SAMLExtensionFormat.EIDAS_FORMAT_NAME);
        request.setEidasNameidFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:transient");
        byte saml[]=getEngine().generateEIDASAuthnRequest(request).getTokenSaml();
        String base64SamlXml=new String(saml);
        assertFalse(base64SamlXml.isEmpty());
        return saml;
    }

    @Test
    public final void testResignAuthnRequest() throws EIDASSAMLEngineException {

        EIDASAuthnRequest request = new EIDASAuthnRequest();

        request.setDestination(destination);
        request.setProviderName(spName);
        request.setPersonalAttributeList(pal);

        // new parameters
        request.setSpSector(spSector);
        request.setSpInstitution(spInstitution);
        request.setSpApplication(spApplication);
        request.setSpCountry(spCountry);
        request.setSPID(spId);
        request.setCitizenCountryCode("ES");
        request.setBinding(EIDASAuthnRequest.BINDING_EMPTY);
        request.setEidasNameidFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");

        try {
            request = getEngine().generateEIDASAuthnRequest(request);
            new StorkExtensionProcessor().configureExtension();
            byte[] b=request.getTokenSaml();
            String marshalled = new String(b, Constants.UTF8_ENCODING);
            String resigned=new String(getEngine().resignEIDASTokenSAML(b));
            assertFalse(resigned.isEmpty());
        }catch(UnsupportedEncodingException uee){
            fail("encoding error "+uee);
        }
    }

}
