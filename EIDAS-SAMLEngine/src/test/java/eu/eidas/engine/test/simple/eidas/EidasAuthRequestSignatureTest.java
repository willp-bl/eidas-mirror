
package eu.eidas.engine.test.simple.eidas;

import eu.eidas.auth.commons.IPersonalAttributeList;
import eu.eidas.auth.commons.PersonalAttribute;
import eu.eidas.auth.commons.PersonalAttributeList;
import eu.eidas.auth.commons.EIDASAuthnRequest;
import eu.eidas.auth.engine.AbstractSAMLEngine;
import eu.eidas.auth.engine.EIDASSAMLEngine;
import eu.eidas.auth.engine.core.SAMLEngineSignI;
import eu.eidas.auth.engine.core.SAMLExtensionFormat;
import eu.eidas.auth.engine.core.eidas.EidasExtensionProcessor;
import eu.eidas.engine.exceptions.SAMLEngineException;
import eu.eidas.engine.exceptions.EIDASSAMLEngineException;

import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.core.AuthnRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.Assert.*;

public class EidasAuthRequestSignatureTest {
	private static final String NAMEID_FORMAT="urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
	private static final String LOA_LOW="http://eidas.europa.eu/LoA/low";
    private final static String SAML_ENGINE_NAME="CONF1";
    /**
     * The engine.
     */

    @Before
    public void setUp(){
    }


    /**
     * Instantiates a new EIDAS authentication request test.
     */
    public EidasAuthRequestSignatureTest() {
        pal = new PersonalAttributeList();

        final PersonalAttribute dateOfBirth = new PersonalAttribute();
        dateOfBirth.setName("DateOfBirth");
        dateOfBirth.setIsRequired(false);
        pal.add(dateOfBirth);

        final PersonalAttribute eIDNumber = new PersonalAttribute();
        eIDNumber.setName("PersonIdentifier");
        eIDNumber.setIsRequired(true);
        pal.add(eIDNumber);

        destination = "http://EidasService.gov.xx/EIDASNODE/ColleagueRequest";
        assertConsumerUrl = "http://EidasConnector.gov.xx/EIDASNODE/ColleagueResponse";

        spName = "University of Oxford";
        spSector = "EDU001";
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
     * The Constant LOG.
     */
    private static final Logger LOG = LoggerFactory
            .getLogger(EidasAuthRequestSignatureTest.class.getName());


    /**
     * Test generate authentication request error personal attribute name error.
     */
    @Test
    public final void testGenerateAuthnRequest() {
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
        request.setCitizenCountryCode("BE");
        request.setMessageFormatName("eidas");
        request.setSPType("public");
        request.setEidasLoA(LOA_LOW);
        request.setEidasNameidFormat(NAMEID_FORMAT);

        SamlEngineInterceptor engineInterceptor=null;
        try {
            engineInterceptor = new SamlEngineInterceptor();
        }catch(EIDASSAMLEngineException exc){
            fail("error while initializing samlengine "+exc);
        }
        assertNotNull(engineInterceptor);
        engineInterceptor.setSignerProperty(SAMLEngineSignI.SIGNATURE_ALGORITHM, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384");
        EIDASAuthnRequest authReq=null;
        try {

            authReq = engineInterceptor.generateAuthnRequest(request);
        } catch (EIDASSAMLEngineException e) {
            LOG.error("Error");
        }
        assertNotNull(authReq);
        byte[] tokenSaml=authReq.getTokenSaml();
        String requestXML=new String(tokenSaml);
        authReq=null;
        try {
            String signingAlgo=engineInterceptor.getSigningAlgo(tokenSaml);
            assertEquals(signingAlgo, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384");
            authReq = engineInterceptor.validateAuthnRequest(tokenSaml);
        }catch (EIDASSAMLEngineException exc){
            LOG.error("Error: "+requestXML);
            fail("error while validating request "+exc);
        }
        assertNotNull(authReq);

        engineInterceptor.setSignerProperty(SAMLEngineSignI.SIGNATURE_ALGORITHM, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        authReq=null;
        try {

            authReq = engineInterceptor.generateAuthnRequest(request);
        } catch (EIDASSAMLEngineException e) {
            LOG.error("Error");
        }
        assertNotNull(authReq);
        tokenSaml=authReq.getTokenSaml();
        authReq=null;
        try {
            String signingAlgo=engineInterceptor.getSigningAlgo(tokenSaml);
            assertEquals(signingAlgo, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
            authReq = engineInterceptor.validateAuthnRequest(tokenSaml);
        }catch (EIDASSAMLEngineException exc){
            LOG.error("Error");
            fail("error while validating request "+exc);
        }
        assertNotNull(authReq);

    }

    private class SamlEngineInterceptor extends AbstractSAMLEngine{
        EIDASSAMLEngine samlEngine=null;
        public SamlEngineInterceptor() throws EIDASSAMLEngineException{
            super(SAML_ENGINE_NAME);
            samlEngine = EIDASSAMLEngine.createSAMLEngine(SAML_ENGINE_NAME);
            samlEngine.setExtensionProcessor(new EidasExtensionProcessor());
        }
        public EIDASAuthnRequest generateAuthnRequest(
                final EIDASAuthnRequest request) throws EIDASSAMLEngineException {
            return samlEngine.generateEIDASAuthnRequest(request);
        }

        public EIDASAuthnRequest validateAuthnRequest(final byte[] tokenSaml)
                throws EIDASSAMLEngineException {
            return samlEngine.validateEIDASAuthnRequest(tokenSaml);
        }
        public void setSignerProperty(String propName, String propValue){
             samlEngine.setSignerProperty(propName, propValue);
        }

        public String getSigningAlgo(
                final byte[] token) throws EIDASSAMLEngineException {
            AuthnRequest unmarshalled=null;
            try {
                unmarshalled = (AuthnRequest)this.unmarshall(token);
            }catch(SAMLEngineException exc){
                fail("error unmarshalling token: "+exc);
            }
            return unmarshalled.getSignature().getSignatureAlgorithm();
        }
        public SAMLExtensionFormat getMessageFormat(){
            return SAMLExtensionFormat.EIDAS10;
        }


    }
}
