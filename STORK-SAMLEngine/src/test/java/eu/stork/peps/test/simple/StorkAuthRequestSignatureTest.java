
package eu.stork.peps.test.simple;

import eu.stork.peps.auth.commons.IPersonalAttributeList;
import eu.stork.peps.auth.commons.PersonalAttribute;
import eu.stork.peps.auth.commons.PersonalAttributeList;
import eu.stork.peps.auth.commons.STORKAuthnRequest;
import eu.stork.peps.auth.engine.AbstractSAMLEngine;
import eu.stork.peps.auth.engine.STORKSAMLEngine;
import eu.stork.peps.auth.engine.core.SAMLEngineSignI;
import eu.stork.peps.auth.engine.core.SAMLExtensionFormat;
import eu.stork.peps.auth.engine.core.stork.StorkExtensionProcessor;
import eu.stork.peps.exceptions.SAMLEngineException;
import eu.stork.peps.exceptions.STORKSAMLEngineException;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.core.AuthnRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;

import static org.junit.Assert.*;

public class StorkAuthRequestSignatureTest {
    private final static String SAML_ENGINE_NAME="CONF1";
    /**
     * The engine.
     */

    @Before
    public void setUp(){
    }


    /**
     * Instantiates a new stork authentication request test.
     */
    public StorkAuthRequestSignatureTest() {
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
            .getLogger(StorkAuthRequestSignatureTest.class.getName());


    /**
     * Test generate authentication request error personal attribute name error.
     */
    @Test
    public final void testGenerateAuthnRequest() {
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
        request.setCitizenCountryCode("BE");

        SamlEngineInterceptor engineInterceptor=null;
        try {
            engineInterceptor = new SamlEngineInterceptor();
        }catch(STORKSAMLEngineException exc){
            fail("error while initializing samlengine "+exc);
        }
        assertNotNull(engineInterceptor);
        engineInterceptor.setSignerProperty(SAMLEngineSignI.SIGNATURE_ALGORITHM, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384");
        STORKAuthnRequest storkReq=null;
        try {

            storkReq = engineInterceptor.generateSTORKAuthnRequest(request);
        } catch (STORKSAMLEngineException e) {
            LOG.error("Error");
        }
        assertNotNull(storkReq);
        byte[] tokenSaml=storkReq.getTokenSaml();
        String requestXML=new String(tokenSaml);
        storkReq=null;
        try {
            String signingAlgo=engineInterceptor.getSigningAlgo(tokenSaml);
            assertEquals(signingAlgo, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384");
            storkReq = engineInterceptor.validateSTORKAuthnRequest(tokenSaml);
        }catch (STORKSAMLEngineException exc){
            LOG.error("Error: "+requestXML);
            fail("error while validating request "+exc);
        }
        assertNotNull(storkReq);

        engineInterceptor.setSignerProperty(SAMLEngineSignI.SIGNATURE_ALGORITHM, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        storkReq=null;
        try {

            storkReq = engineInterceptor.generateSTORKAuthnRequest(request);
        } catch (STORKSAMLEngineException e) {
            LOG.error("Error");
        }
        assertNotNull(storkReq);
        tokenSaml=storkReq.getTokenSaml();
        storkReq=null;
        try {
            String signingAlgo=engineInterceptor.getSigningAlgo(tokenSaml);
            assertEquals(signingAlgo, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
            storkReq = engineInterceptor.validateSTORKAuthnRequest(tokenSaml);
        }catch (STORKSAMLEngineException exc){
            LOG.error("Error");
            fail("error while validating request "+exc);
        }
        assertNotNull(storkReq);

    }

    private class SamlEngineInterceptor extends AbstractSAMLEngine{
        STORKSAMLEngine samlEngine=null;
        public SamlEngineInterceptor() throws STORKSAMLEngineException{
            super(SAML_ENGINE_NAME);
            samlEngine = STORKSAMLEngine.createSTORKSAMLEngine(SAML_ENGINE_NAME);
            samlEngine.setExtensionProcessor(new StorkExtensionProcessor());
        }
        public STORKAuthnRequest generateSTORKAuthnRequest(
                final STORKAuthnRequest request) throws STORKSAMLEngineException {
            return samlEngine.generateSTORKAuthnRequest(request);
        }

        public STORKAuthnRequest validateSTORKAuthnRequest(final byte[] tokenSaml)
                throws STORKSAMLEngineException {
            return samlEngine.validateSTORKAuthnRequest(tokenSaml);
        }
        public void setSignerProperty(String propName, String propValue){
             samlEngine.setSignerProperty(propName, propValue);
        }

        public String getSigningAlgo(
                final byte[] token) throws STORKSAMLEngineException {
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
