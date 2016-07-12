package eu.stork.peps.tests;

import eu.stork.peps.auth.commons.*;
import junit.framework.Assert;
import org.joda.time.DateTime;
import org.junit.Test;

/**
 * Commons Single bean test case
 */
public class SingleBeanTestCase {
    private static final String COUNTRY_ID      = "KL";
    private static final String COUNTRY_NAME    = "KLINGON";
    private static final String COUNTRY_CODE_BELGIUM = "BEL";
    private static final String ERROR_MSG_DUMMY = "DUMMY";

    @Test
    public void testCountrySetGet() {
        Country country = new Country(COUNTRY_ID, COUNTRY_NAME);
        Assert.assertSame(country.getCountryId(), COUNTRY_ID);
        Assert.assertSame(country.getCountryName(), COUNTRY_NAME);
        Country country2 = new Country("", "");
        country2.setCountryId(COUNTRY_ID);
        country2.setCountryName(COUNTRY_NAME);
        Assert.assertEquals(country, country2);
    }
    @Test
    public void testCountryCode() {
        Assert.assertTrue(CountryCodes.hasCountryCodeAlpha3(COUNTRY_CODE_BELGIUM));
        Assert.assertFalse(CountryCodes.hasCountryCodeAlpha3(""));
    }

    @Test
    public void testSTORKSubStatusCode() {
        Assert.assertEquals(STORKSubStatusCode.AUTHN_FAILED_URI.toString(), "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed");
    }

    @Test
    public void testPepsError() {
        Assert.assertEquals(PEPSErrors.MISSING_SESSION_ID.errorMessage(), PEPSErrors.MISSING_SESSION_ID.toString() + PEPSErrors.MESSAGE_CONSTANT);
        Assert.assertEquals(PEPSErrors.MISSING_SESSION_ID.errorMessage(ERROR_MSG_DUMMY),
                PEPSErrors.MISSING_SESSION_ID.toString() + PEPSErrors.DOT_SEPARATOR + ERROR_MSG_DUMMY + PEPSErrors.MESSAGE_CONSTANT);
        Assert.assertEquals(PEPSErrors.MISSING_SESSION_ID.errorCode(), PEPSErrors.MISSING_SESSION_ID.toString() + PEPSErrors.CODE_CONSTANT);
        Assert.assertEquals(PEPSErrors.MISSING_SESSION_ID.errorCode(ERROR_MSG_DUMMY),
                PEPSErrors.MISSING_SESSION_ID.toString() + PEPSErrors.DOT_SEPARATOR + ERROR_MSG_DUMMY + PEPSErrors.CODE_CONSTANT);
    }

    @Test
    public void testAuthnRequest()throws CloneNotSupportedException{
        int QAAL = 3;
        final STORKAuthnRequest storkAuthnRequest1 = new STORKAuthnRequest();
        storkAuthnRequest1.setAlias("testAlias");
        storkAuthnRequest1.setSPID("EDU001-APP001-APP001");
        storkAuthnRequest1.setCitizenCountryCode("ES");
        storkAuthnRequest1.setSpCountry("EN");
        storkAuthnRequest1.setIssuer("testIssuer");
        storkAuthnRequest1.setTokenSaml(null);
        storkAuthnRequest1.setTokenSaml("6E97069A1754ED".getBytes());
        storkAuthnRequest1.setCountry("UK");
        storkAuthnRequest1.setQaa(QAAL);
        storkAuthnRequest1.setAssertionConsumerServiceURL("http://C-PEPS.gov.xx/PEPS/ColleagueRequest");
        storkAuthnRequest1.setDestination("http://C-PEPS.gov.xx/PEPS/ColleagueRequest");
        storkAuthnRequest1.setSamlId("QDS2QFD");
        storkAuthnRequest1.setProviderName("University of Oxford");
        PersonalAttributeList paler = new PersonalAttributeList();

        final PersonalAttribute eIDNumber = new PersonalAttribute();
        eIDNumber.setName("eIdentifier");
        eIDNumber.setIsRequired(true);
        paler.add(eIDNumber);
        storkAuthnRequest1.setPersonalAttributeList(paler);
        storkAuthnRequest1.setPersonalAttributeList(null);

        storkAuthnRequest1.setDistinguishedName("TestDistinguishedName");
        storkAuthnRequest1.setSpSector("EDU001");
        storkAuthnRequest1.setSpInstitution("OXF001");
        storkAuthnRequest1.setSpApplication("APP001");
        storkAuthnRequest1.setEIDCrossBorderShare(true);
        storkAuthnRequest1.setEIDCrossSectorShare(true);
        storkAuthnRequest1.setEIDSectorShare(true);
        STORKAuthnRequest storkAuthnRequest2 = (STORKAuthnRequest) storkAuthnRequest1.clone();

        Assert.assertEquals(storkAuthnRequest1.getAlias(), storkAuthnRequest2.getAlias());
        Assert.assertEquals(storkAuthnRequest1.getAssertionConsumerServiceURL(), storkAuthnRequest2.getAssertionConsumerServiceURL());
        Assert.assertEquals(storkAuthnRequest1.getCitizenCountryCode(), storkAuthnRequest2.getCitizenCountryCode());
        Assert.assertEquals(storkAuthnRequest1.getCountry(), storkAuthnRequest2.getCountry());
        Assert.assertEquals(storkAuthnRequest1.getDestination(), storkAuthnRequest2.getDestination());
        Assert.assertEquals(storkAuthnRequest1.getDistinguishedName(), storkAuthnRequest2.getDistinguishedName());
        Assert.assertEquals(storkAuthnRequest1.getIssuer(), storkAuthnRequest2.getIssuer());
        Assert.assertEquals(storkAuthnRequest1.getProviderName(), storkAuthnRequest2.getProviderName());
        Assert.assertEquals(storkAuthnRequest1.getQaa(), storkAuthnRequest2.getQaa());
        Assert.assertEquals(storkAuthnRequest1.getSamlId(), storkAuthnRequest2.getSamlId());
        Assert.assertEquals(storkAuthnRequest1.getSpCountry(), storkAuthnRequest2.getSpCountry());
        Assert.assertEquals(storkAuthnRequest1.getSPID(), storkAuthnRequest2.getSPID());
        Assert.assertNotSame(storkAuthnRequest1.getTokenSaml().toString(), storkAuthnRequest2.getTokenSaml().toString());
        Assert.assertEquals(storkAuthnRequest1.getSpSector(), storkAuthnRequest2.getSpSector());
        Assert.assertEquals(storkAuthnRequest1.getSpInstitution(), storkAuthnRequest2.getSpInstitution());
        Assert.assertEquals(storkAuthnRequest1.getSpApplication(), storkAuthnRequest2.getSpApplication());
        Assert.assertEquals(storkAuthnRequest1.isEIDCrossBorderShare(), storkAuthnRequest2.isEIDCrossBorderShare());
        Assert.assertEquals(storkAuthnRequest1.isEIDCrossSectorShare(), storkAuthnRequest2.isEIDCrossSectorShare());
        Assert.assertEquals(storkAuthnRequest1.isEIDSectorShare(), storkAuthnRequest2.isEIDSectorShare());
    }
    @Test
    public void testAuthnResponse()throws CloneNotSupportedException{
        int QAAL = 3;
        final STORKAuthnResponse storkAuthnResponse = new STORKAuthnResponse();
        storkAuthnResponse.setTokenSaml(null);
        storkAuthnResponse.setTokenSaml("6E97069A1754ED".getBytes());
        storkAuthnResponse.setCountry("UK");
        storkAuthnResponse.setSamlId("QDS2QFD");
        storkAuthnResponse.setAudienceRestriction("PUBLIC");
        storkAuthnResponse.setInResponseTo("6E97069A1754ED");
        storkAuthnResponse.setFail(false);
        storkAuthnResponse.setStatusCode(STORKStatusCode.REQUESTER_URI.toString());
        storkAuthnResponse.setSubStatusCode(STORKSubStatusCode.AUTHN_FAILED_URI.toString());
        storkAuthnResponse.setMessage("TEST");
        storkAuthnResponse.setNotBefore(new DateTime());
        storkAuthnResponse.setNotOnOrAfter(new DateTime());
        PersonalAttributeList paler = new PersonalAttributeList();

        final PersonalAttribute eIDNumber = new PersonalAttribute();
        eIDNumber.setName("eIdentifier");
        eIDNumber.setIsRequired(true);
        paler.add(eIDNumber);
        storkAuthnResponse.setPersonalAttributeList(paler);
        storkAuthnResponse.setPersonalAttributeList(null);

        Assert.assertNotNull(storkAuthnResponse.getTokenSaml());
        Assert.assertNotNull(storkAuthnResponse.getCountry());
        Assert.assertNotNull(storkAuthnResponse.getSamlId());
        Assert.assertNotNull(storkAuthnResponse.getAudienceRestriction());
        Assert.assertNotNull(storkAuthnResponse.getInResponseTo());
        Assert.assertNotNull(storkAuthnResponse.isFail());
        Assert.assertNotNull(storkAuthnResponse.getStatusCode());
        Assert.assertNotNull(storkAuthnResponse.getSubStatusCode());
        Assert.assertNotNull(storkAuthnResponse.getNotBefore());
        Assert.assertNotNull(storkAuthnResponse.getNotOnOrAfter());
        Assert.assertNotNull(storkAuthnResponse.getPersonalAttributeList());
        Assert.assertNotNull(storkAuthnResponse.getMessage());
    }
    @Test
    public void testPEPSValue(){
        Assert.assertEquals(PEPSValues.ATTRIBUTE.index(1), PEPSValues.ATTRIBUTE.toString()+"1.id");
        Assert.assertEquals(PEPSValues.ATTRIBUTE.value(1), PEPSValues.ATTRIBUTE.toString()+"1.value");
        Assert.assertEquals(PEPSValues.ATTRIBUTE.name(1), PEPSValues.ATTRIBUTE.toString()+"1.name");
        Assert.assertEquals(PEPSValues.ATTRIBUTE.url(1), PEPSValues.ATTRIBUTE.toString()+"1.url");
        Assert.assertEquals(PEPSValues.ATTRIBUTE.skew(1), PEPSValues.ATTRIBUTE.toString() + "1.skew");
    }
}
