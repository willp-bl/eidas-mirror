package eu.eidas.tests;

import eu.eidas.auth.commons.*;
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
    public void testEIDASSubStatusCode() {
        Assert.assertEquals(EIDASSubStatusCode.AUTHN_FAILED_URI.toString(), "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed");
    }

    @Test
    public void testEidasNodeError() {
        Assert.assertEquals(EIDASErrors.MISSING_SESSION_ID.errorMessage(), EIDASErrors.MISSING_SESSION_ID.toString() + EIDASErrors.MESSAGE_CONSTANT);
        Assert.assertEquals(EIDASErrors.MISSING_SESSION_ID.errorMessage(ERROR_MSG_DUMMY),
                EIDASErrors.MISSING_SESSION_ID.toString() + EIDASErrors.DOT_SEPARATOR + ERROR_MSG_DUMMY + EIDASErrors.MESSAGE_CONSTANT);
        Assert.assertEquals(EIDASErrors.MISSING_SESSION_ID.errorCode(), EIDASErrors.MISSING_SESSION_ID.toString() + EIDASErrors.CODE_CONSTANT);
        Assert.assertEquals(EIDASErrors.MISSING_SESSION_ID.errorCode(ERROR_MSG_DUMMY),
                EIDASErrors.MISSING_SESSION_ID.toString() + EIDASErrors.DOT_SEPARATOR + ERROR_MSG_DUMMY + EIDASErrors.CODE_CONSTANT);
    }

    @Test
    public void testAuthnRequest()throws CloneNotSupportedException{
        int QAAL = 3;
        final EIDASAuthnRequest eidasAuthnRequest1 = new EIDASAuthnRequest();
        eidasAuthnRequest1.setAlias("testAlias");
        eidasAuthnRequest1.setSPID("EDU001-APP001-APP001");
        eidasAuthnRequest1.setCitizenCountryCode("ES");
        eidasAuthnRequest1.setSpCountry("EN");
        eidasAuthnRequest1.setIssuer("testIssuer");
        eidasAuthnRequest1.setTokenSaml(null);
        eidasAuthnRequest1.setTokenSaml("6E97069A1754ED".getBytes());
        eidasAuthnRequest1.setCountry("UK");
        eidasAuthnRequest1.setQaa(QAAL);
        eidasAuthnRequest1.setAssertionConsumerServiceURL("http://node.gov.xx/node/ColleagueRequest");
        eidasAuthnRequest1.setDestination("http://node.gov.xx/node/ColleagueRequest");
        eidasAuthnRequest1.setSamlId("QDS2QFD");
        eidasAuthnRequest1.setProviderName("University of Oxford");
        PersonalAttributeList paler = new PersonalAttributeList();

        final PersonalAttribute eIDNumber = new PersonalAttribute();
        eIDNumber.setName("eIdentifier");
        eIDNumber.setIsRequired(true);
        paler.add(eIDNumber);
        eidasAuthnRequest1.setPersonalAttributeList(paler);
        eidasAuthnRequest1.setPersonalAttributeList(null);

        eidasAuthnRequest1.setDistinguishedName("TestDistinguishedName");
        eidasAuthnRequest1.setSpSector("EDU001");
        eidasAuthnRequest1.setSpInstitution("OXF001");
        eidasAuthnRequest1.setSpApplication("APP001");
        eidasAuthnRequest1.setEIDCrossBorderShare(true);
        eidasAuthnRequest1.setEIDCrossSectorShare(true);
        eidasAuthnRequest1.setEIDSectorShare(true);
        EIDASAuthnRequest eidasAuthnRequest2 = (EIDASAuthnRequest) eidasAuthnRequest1.clone();

        Assert.assertEquals(eidasAuthnRequest1.getAlias(), eidasAuthnRequest2.getAlias());
        Assert.assertEquals(eidasAuthnRequest1.getAssertionConsumerServiceURL(), eidasAuthnRequest2.getAssertionConsumerServiceURL());
        Assert.assertEquals(eidasAuthnRequest1.getCitizenCountryCode(), eidasAuthnRequest2.getCitizenCountryCode());
        Assert.assertEquals(eidasAuthnRequest1.getCountry(), eidasAuthnRequest2.getCountry());
        Assert.assertEquals(eidasAuthnRequest1.getDestination(), eidasAuthnRequest2.getDestination());
        Assert.assertEquals(eidasAuthnRequest1.getDistinguishedName(), eidasAuthnRequest2.getDistinguishedName());
        Assert.assertEquals(eidasAuthnRequest1.getIssuer(), eidasAuthnRequest2.getIssuer());
        Assert.assertEquals(eidasAuthnRequest1.getProviderName(), eidasAuthnRequest2.getProviderName());
        Assert.assertEquals(eidasAuthnRequest1.getQaa(), eidasAuthnRequest2.getQaa());
        Assert.assertEquals(eidasAuthnRequest1.getSamlId(), eidasAuthnRequest2.getSamlId());
        Assert.assertEquals(eidasAuthnRequest1.getSpCountry(), eidasAuthnRequest2.getSpCountry());
        Assert.assertEquals(eidasAuthnRequest1.getSPID(), eidasAuthnRequest2.getSPID());
        Assert.assertNotSame(eidasAuthnRequest1.getTokenSaml().toString(), eidasAuthnRequest2.getTokenSaml().toString());
        Assert.assertEquals(eidasAuthnRequest1.getSpSector(), eidasAuthnRequest2.getSpSector());
        Assert.assertEquals(eidasAuthnRequest1.getSpInstitution(), eidasAuthnRequest2.getSpInstitution());
        Assert.assertEquals(eidasAuthnRequest1.getSpApplication(), eidasAuthnRequest2.getSpApplication());
        Assert.assertEquals(eidasAuthnRequest1.isEIDCrossBorderShare(), eidasAuthnRequest2.isEIDCrossBorderShare());
        Assert.assertEquals(eidasAuthnRequest1.isEIDCrossSectorShare(), eidasAuthnRequest2.isEIDCrossSectorShare());
        Assert.assertEquals(eidasAuthnRequest1.isEIDSectorShare(), eidasAuthnRequest2.isEIDSectorShare());
    }
    @Test
    public void testAuthnResponse()throws CloneNotSupportedException{
        int QAAL = 3;
        final EIDASAuthnResponse eidasAuthnResponse = new EIDASAuthnResponse();
        eidasAuthnResponse.setTokenSaml(null);
        eidasAuthnResponse.setTokenSaml("6E97069A1754ED".getBytes());
        eidasAuthnResponse.setCountry("UK");
        eidasAuthnResponse.setSamlId("QDS2QFD");
        eidasAuthnResponse.setAudienceRestriction("PUBLIC");
        eidasAuthnResponse.setInResponseTo("6E97069A1754ED");
        eidasAuthnResponse.setFail(false);
        eidasAuthnResponse.setStatusCode(EIDASStatusCode.REQUESTER_URI.toString());
        eidasAuthnResponse.setSubStatusCode(EIDASSubStatusCode.AUTHN_FAILED_URI.toString());
        eidasAuthnResponse.setMessage("TEST");
        eidasAuthnResponse.setNotBefore(new DateTime());
        eidasAuthnResponse.setNotOnOrAfter(new DateTime());
        PersonalAttributeList paler = new PersonalAttributeList();

        final PersonalAttribute eIDNumber = new PersonalAttribute();
        eIDNumber.setName("eIdentifier");
        eIDNumber.setIsRequired(true);
        paler.add(eIDNumber);
        eidasAuthnResponse.setPersonalAttributeList(paler);
        eidasAuthnResponse.setPersonalAttributeList(null);

        Assert.assertNotNull(eidasAuthnResponse.getTokenSaml());
        Assert.assertNotNull(eidasAuthnResponse.getCountry());
        Assert.assertNotNull(eidasAuthnResponse.getSamlId());
        Assert.assertNotNull(eidasAuthnResponse.getAudienceRestriction());
        Assert.assertNotNull(eidasAuthnResponse.getInResponseTo());
        Assert.assertNotNull(eidasAuthnResponse.isFail());
        Assert.assertNotNull(eidasAuthnResponse.getStatusCode());
        Assert.assertNotNull(eidasAuthnResponse.getSubStatusCode());
        Assert.assertNotNull(eidasAuthnResponse.getNotBefore());
        Assert.assertNotNull(eidasAuthnResponse.getNotOnOrAfter());
        Assert.assertNotNull(eidasAuthnResponse.getPersonalAttributeList());
        Assert.assertNotNull(eidasAuthnResponse.getMessage());
    }
    @Test
    public void testEIDASNodeValue(){
        Assert.assertEquals(EIDASValues.ATTRIBUTE.index(1), EIDASValues.ATTRIBUTE.toString()+"1.id");
        Assert.assertEquals(EIDASValues.ATTRIBUTE.value(1), EIDASValues.ATTRIBUTE.toString()+"1.value");
        Assert.assertEquals(EIDASValues.ATTRIBUTE.name(1), EIDASValues.ATTRIBUTE.toString()+"1.name");
        Assert.assertEquals(EIDASValues.ATTRIBUTE.url(1), EIDASValues.ATTRIBUTE.toString()+"1.url");
        Assert.assertEquals(EIDASValues.ATTRIBUTE.skew(1), EIDASValues.ATTRIBUTE.toString() + "1.skew");
    }
}
