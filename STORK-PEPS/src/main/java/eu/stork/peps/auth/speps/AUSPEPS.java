/*
 * This work is Open Source and licensed by the European Commission under the
 * conditions of the European Public License v1.1 
 *  
 * (http://www.osor.eu/eupl/european-union-public-licence-eupl-v.1.1); 
 * 
 * any use of this file implies acceptance of the conditions of this license. 
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS,  WITHOUT 
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the 
 * License for the specific language governing permissions and limitations 
 * under the License.
 */
package eu.stork.peps.auth.speps;

import java.nio.charset.Charset;
import java.util.List;
import java.util.Map;

import eu.stork.peps.ApplicationContextProvider;
import eu.stork.peps.auth.commons.*;
import eu.stork.peps.auth.commons.exceptions.InvalidParameterPEPSException;
import eu.stork.peps.auth.commons.exceptions.StorkPEPSException;
import eu.stork.peps.auth.engine.core.SAMLExtensionFormat;
import eu.stork.peps.auth.engine.core.eidas.SPType;
import eu.stork.peps.utils.EidasAttributesUtil;
import eu.stork.peps.utils.PEPSValidationUtil;
import org.apache.commons.lang.CharEncoding;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.stork.peps.auth.commons.exceptions.InvalidSessionPEPSException;
import org.springframework.context.ApplicationContext;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * The AUSPEPS class serves as the middle-man in the communications between the
 * Service Provider and the CPEPS. It is responsible for handling the requests
 * coming from the Service Provider and forward them to the CPEPS, and
 * vice-versa.
 *
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com, hugo.magalhaes@multicert.com,
 *         paulo.ribeiro@multicert.com
 * @version $Revision: 1.58 $, $Date: 2011-02-18 02:02:39 $
 * @see ISPEPSService
 */
public final class AUSPEPS implements ISPEPSService{

    /**
     * Logger object.
     */
    private static final Logger LOG = LoggerFactory.getLogger(AUSPEPS.class.getName());
    /**
     * Service for country related operations.
     */
    private ISPEPSCountrySelectorService countryService;

    /**
     * Service for SAML related operations.
     */
    private ISPEPSSAMLService samlService;

    /**
     * Service for translation related operations.
     */
    private ISPEPSTranslatorService transService;

    /**
     * Default SP Application.
     */
    private String spApplication;

    /**
     * Default SP Country.
     */
    private String spCountry;

    /**
     * Default SP Institution.
     */
    private String spInstitution;

    /**
     * Default SP Sector.
     */
    private String spSector;

    /**
     * SPEPS configuration.
     */
    private AUSPEPSUtil spepsUtil;

    /**
     * {@inheritDoc}
     */
    public byte[] processCountrySelector(final Map<String, String> parameters) {

        // validates if a SP has permission to access a determined attribute
        final STORKAuthnRequest authData =
                getCountryService().checkCountrySelectorRequest(parameters,
                        getSamlService());
        // As the CountrySelectorAction can be used to generate SAML Token for
        // different SPs, then we must fulfil the following SAML attributes
        // with NOT_AVAILABLE value.
        if (StringUtils.isEmpty(authData.getSpApplication())) {
            authData.setSpApplication(spApplication);
        }

        if (StringUtils.isEmpty(authData.getSpCountry())) {
            authData.setSpCountry(spCountry);
        }

        if (StringUtils.isEmpty(authData.getSpInstitution())) {
            authData.setSpInstitution(spInstitution);
        }

        if (StringUtils.isEmpty(authData.getSpSector())) {
            authData.setSpSector(spSector);
        }

        // generate SAML Token
        return samlService.generateSpAuthnRequest(authData).getTokenSaml();
    }

    /**
     * {@inheritDoc}
     */
    public List<Country> getCountrySelectorList() {
        // creates the country selector list
        return getCountryService().createCountrySelector();
    }

    /**
     * {@inheritDoc}
     */
    public STORKAuthnRequest getAuthenticationRequest(
            final Map<String, String> parameters, final IStorkSession session) {

        LOG.trace("Getting SAML Token");
        final byte[] spSamlToken =
                samlService.getSAMLToken(parameters,
                        PEPSErrors.SPROVIDER_SELECTOR_INVALID_SAML.name(), true);

        // validates the SAML Token
        STORKAuthnRequest authData =
                samlService.processAuthenticationRequest(spSamlToken, parameters);
        final String relayStateCons = PEPSParameters.RELAY_STATE.toString();
        if (parameters.containsKey(relayStateCons)) {
            LOG.trace("Saving relay state.");
            session.put(relayStateCons, parameters.get(relayStateCons));
        }
        session.put(PEPSParameters.SP_URL.toString(), authData.getAssertionConsumerServiceURL());
        session.put(PEPSParameters.ERROR_REDIRECT_URL.toString(), authData.getAssertionConsumerServiceURL());
        session.put(PEPSParameters.SAML_IN_RESPONSE_TO.toString(), authData.getSamlId());

        LOG.debug("== SESSION : AUSPEPS.getAuthenticationRequest Called, size is " + session.size());
        if(spepsUtil!=null && Boolean.valueOf(spepsUtil.getConfigs().getProperty(PEPSParameters.VALIDATE_BINDING.toString()))) {
            PEPSValidationUtil.validateBinding(authData, parameters.get(PEPSParameters.HTTP_METHOD.toString()), PEPSErrors.SPROVIDER_SELECTOR_INVALID_SAML);
        }

        if(spepsUtil!=null && SAMLExtensionFormat.EIDAS10.getName().equalsIgnoreCase(authData.getMessageFormatName())){
            prepareEidasRequest(authData, parameters);
        }else {
            authData.setAssertionConsumerServiceURL(parameters.get(PEPSParameters.ASSERTION_CONSUMER_S_URL.toString()));
        }

        // normalize attributes to STORK format
        final IPersonalAttributeList pal =
                transService.normaliseAttributeNamesToStork(authData
                        .getPersonalAttributeList());
        authData.setPersonalAttributeList(pal);

        // generate SAML Token
        authData = samlService.generateCpepsAuthnRequest(authData);
        session.put(PEPSParameters.AUTH_REQUEST.toString(), authData);

        final byte[] samlToken = authData.getTokenSaml();
        authData.setTokenSaml(this.sendRedirect(samlToken).getBytes(Charset.forName("UTF-8")));

        final String remoteAddrCons = PEPSParameters.REMOTE_ADDR.toString();
        session.put(remoteAddrCons, parameters.get(remoteAddrCons));
        LOG.debug("== SESSION : AUSPEPS.getAuthenticationRequest Called, size is " + session.size());

        return authData;
    }

    private void prepareEidasRequest(final STORKAuthnRequest authData,final Map<String, String> parameters){
        if(spepsUtil!=null && !Boolean.parseBoolean(spepsUtil.getConfigs().getProperty(PEPSValues.DISABLE_CHECK_MANDATORY_ATTRIBUTES.toString())) &&
            !EidasAttributesUtil.checkMandatoryAttributeSets(authData.getPersonalAttributeList())){
            LOG.error("BUSINESS EXCEPTION : incomplete mandatory set");
            throw new StorkPEPSException(PEPSUtil.getConfig(PEPSErrors.EIDAS_MANDATORY_ATTRIBUTES.errorCode()), PEPSUtil.getConfig(PEPSErrors.EIDAS_MANDATORY_ATTRIBUTES.errorMessage()));
        }
        LOG.trace("do not fill in the assertion url");
        authData.setAssertionConsumerServiceURL(null);
        authData.setBinding(null);
        samlService.filterServiceSupportedAttrs(authData, parameters);
        if(!StringUtils.isEmpty(authData.getSPType()) && spepsUtil!=null && spepsUtil.getConfigs().containsKey(PEPSValues.EIDAS_SPTYPE.toString()) &&
                !spepsUtil.getConfigs().getProperty(PEPSValues.EIDAS_SPTYPE.toString()).equalsIgnoreCase(authData.getSPType())   ){
            LOG.error("BUSINESS EXCEPTION : SPType "+authData.getSPType() +"is not supported ");
            throw new StorkPEPSException(PEPSUtil.getConfig(PEPSErrors.SPEPS_INVALID_SPTYPE.errorCode()), PEPSUtil.getConfig(PEPSErrors.SPEPS_INVALID_SPTYPE.errorMessage()));
        }
        if(spepsUtil!=null && !StringUtils.isEmpty(spepsUtil.getConfigs().getProperty(PEPSValues.EIDAS_SPTYPE.toString()))){
            //only the SPType in the connector's metadata will remain active
            authData.setSPType(null);
        }else if(StringUtils.isEmpty(authData.getSPType())){
            authData.setSPType(SPType.DEFAULT_VALUE);
        }

    }
    /**
     * {@inheritDoc}
     */
    public STORKAuthnRequest getAuthenticationResponse(
            final Map<String, String> parameters, final IStorkSession session) {

        final String authReqCons = PEPSParameters.AUTH_REQUEST.toString();
        final String inRespCons = PEPSParameters.SAML_IN_RESPONSE_TO.toString();


        if (session.isEmpty() || session.get(authReqCons) == null
                || session.get(inRespCons) == null) {
            LOG.info("BUSINESS EXCEPTION : Session is missing or invalid");

            throw new InvalidSessionPEPSException(
                    PEPSUtil.getConfig(PEPSErrors.INVALID_SESSION.errorCode()),
                    PEPSUtil.getConfig(PEPSErrors.INVALID_SESSION.errorMessage()));
        }

        LOG.trace("Getting SAML Token");
        final byte[] samlToken =
                samlService.getSAMLToken(parameters,
                        PEPSErrors.COLLEAGUE_RESP_INVALID_SAML.name(), false);

        // validates SAML Token
        STORKAuthnRequest authData =
                (STORKAuthnRequest) session.get(PEPSParameters.AUTH_REQUEST.toString());

        final String ipUserAddress =
                (String) session.get(PEPSParameters.REMOTE_ADDR.toString());
        final STORKAuthnRequest spAuthData = new STORKAuthnRequest();
        spAuthData.setAssertionConsumerServiceURL((String) session
                .get(PEPSParameters.SP_URL.toString()));
        spAuthData.setSamlId((String) session.get(inRespCons));
        spAuthData.setIssuer(authData.getIssuer());
        spAuthData.setMessageFormatName(authData.getMessageFormatName());
        spAuthData.setEidasNameidFormat(authData.getEidasNameidFormat());
        authData =
                samlService.processAuthenticationResponse(samlToken, authData,
                        spAuthData, ipUserAddress);

        // normalizes attributes from STORK format
        final IPersonalAttributeList pal =
                transService.normaliseAttributeNamesFromStork(authData
                        .getPersonalAttributeList());
        if(spepsUtil!=null && !Boolean.parseBoolean(spepsUtil.getConfigs().getProperty(PEPSValues.DISABLE_CHECK_MANDATORY_ATTRIBUTES.toString())) &&
            !EidasAttributesUtil.checkMandatoryAttributeSets(pal)){
            throw new StorkPEPSException(PEPSUtil.getConfig(PEPSErrors.EIDAS_MANDATORY_ATTRIBUTES.errorCode()), PEPSUtil.getConfig(PEPSErrors.EIDAS_MANDATORY_ATTRIBUTES.errorMessage()));
        }
        spAuthData.setPersonalAttributeList(pal);
        spAuthData.setCountry(authData.getCountry());
        spAuthData.setEidasLoA(authData.getEidasLoA());

        LOG.trace("Setting ATTRIBUTE_LIST_PARAM");

        final byte[] samlTokenResponse =
                samlService.generateAuthenticationResponse(spAuthData, ipUserAddress);

        spAuthData.setTokenSaml(this.sendRedirect(samlTokenResponse).getBytes(Charset.forName("UTF-8")));

        return spAuthData;
    }

    /**
     * Encodes, {@link com.sun.org.apache.xml.internal.security.utils.Base64}, a SAML Token.
     *
     * @param samlToken The Saml Token to encode.
     * @return The encoded SAML Token.
     */
    public String sendRedirect(final byte[] samlToken) {

        LOG.trace("Setting attribute SAML_TOKEN_PARAM");
        return PEPSUtil.encodeSAMLToken(samlToken);
    }

    /**
     * Setter for countryService.
     *
     * @param theCountryService The countryService to set.
     * @see ISPEPSCountrySelectorService
     */
    public void setCountryService(
            final ISPEPSCountrySelectorService theCountryService) {

        this.countryService = theCountryService;
    }

    /**
     * Getter for countryService.
     *
     * @return The countryService value.
     * @see ISPEPSCountrySelectorService
     */
    public ISPEPSCountrySelectorService getCountryService() {
        return countryService;
    }

    /**
     * Setter for samlService.
     *
     * @param theSamlService The samlService to set.
     * @see ISPEPSSAMLService
     */
    public void setSamlService(final ISPEPSSAMLService theSamlService) {
        this.samlService = theSamlService;
    }

    /**
     * Getter for samlService.
     *
     * @return The samlService value.
     * @see ISPEPSSAMLService
     */
    public ISPEPSSAMLService getSamlService() {
        return samlService;
    }

    /**
     * Setter for transService.
     *
     * @param nTransService The new transService value.
     * @see ISPEPSTranslatorService
     */
    public void setTransService(final ISPEPSTranslatorService nTransService) {
        this.transService = nTransService;
    }

    /**
     * Getter for transService.
     *
     * @return The transService value.
     * @see ISPEPSTranslatorService
     */
    public ISPEPSTranslatorService getTransService() {
        return transService;
    }

    /**
     * Getter for spApplication.
     *
     * @return The spApplication value.
     */
    public String getSpApplication() {
        return spApplication;
    }

    /**
     * Setter for default spApplication.
     *
     * @param nSpApplication The new spApplication value.
     */
    public void setSpApplication(final String nSpApplication) {
        this.spApplication = nSpApplication;
    }

    /**
     * Getter for spCountry.
     *
     * @return The spCountry value.
     */
    public String getSpCountry() {
        return spCountry;
    }

    /**
     * Setter for default spCountry.
     *
     * @param nSpCountry The new spCountry value.
     */
    public void setSpCountry(final String nSpCountry) {
        this.spCountry = nSpCountry;
    }

    /**
     * Getter for spInstitution.
     *
     * @return The spInstitution value.
     */
    public String getSpInstitution() {
        return spInstitution;
    }

    /**
     * Setter for default spInstitution.
     *
     * @param nSpInstitution The new spInstitution value.
     */
    public void setSpInstitution(final String nSpInstitution) {
        this.spInstitution = nSpInstitution;
    }

    /**
     * Getter for spSector.
     *
     * @return The spSector value.
     */
    public String getSpSector() {
        return spSector;
    }

    /**
     * Setter for default spSector.
     *
     * @param nSpSector The new spSector value.
     */
    public void setSpSector(final String nSpSector) {
        this.spSector = nSpSector;
    }


    public boolean isPluginResponse(HttpServletRequest request){
        CountrySpecificService specificCountry= getCountryHandler(request);
        return specificCountry!=null;
    }

    /**
     *
     * @param request
     * @param response
     * @param context
     * @param storkSession
     * @param parameters
     * @return the plugin response, which can be either the final response or a redirection to the next page (depends on the plugin)
     */
    public String processPluginResponse(final HttpServletRequest request, final HttpServletResponse response, final ServletContext context, final IStorkSession storkSession, final Map<String, String> parameters){
        CountrySpecificService specificCountry= getCountryHandler(request);
        if(specificCountry==null) {
            return null;
        }
        String sAMLResponse=null;
        if(specificCountry.isResponseReady(request,storkSession)) {
            ISPEPSSAMLService localSamlService = getApplicationContext().getBean(ISPEPSSAMLService.class);
            final STORKAuthnRequest authData = (STORKAuthnRequest) storkSession.get(PEPSParameters.AUTH_REQUEST.toString());
            final String spReqID = (String)storkSession.get(PEPSParameters.SAML_IN_RESPONSE_TO.toString());
            IPersonalAttributeList attributeList = getPluginAttributeList(request, storkSession, specificCountry);
            if(authData != null) {
                authData.setPersonalAttributeList(attributeList);
            }
            if(!attributeList.isEmpty()) {
                String authDataOriginalID=authData.getSamlId();
                authData.setAssertionConsumerServiceURL((String) storkSession
                        .get(PEPSParameters.SP_URL.toString()));
                if(spReqID!=null) {
                    authData.setSamlId(spReqID);
                }
                byte[] authResponse = localSamlService.generateAuthenticationResponse(authData, parameters.get(PEPSParameters.REMOTE_ADDR.toString()));
                sAMLResponse = new String(PEPSUtil.encodeSAMLToken(authResponse).getBytes(Charset.forName(CharEncoding.UTF_8)), Charset.forName(CharEncoding.UTF_8));
                authData.setSamlId(authDataOriginalID);
            }
            storkSession.clear();
            if (authData != null) {
                samlService.checkMandatoryAttributes(authData, parameters.get(PEPSParameters.REMOTE_ADDR.toString()));
            }
        }else{
            //redirection may needed (there is an intermediary step)
            specificCountry.performNextStep(context, request, response, storkSession);
        }
        return sAMLResponse;

    }

    private IPersonalAttributeList getPluginAttributeList(final HttpServletRequest request, final IStorkSession storkSession,CountrySpecificService specificCountry){
        if(request.getParameter(CountrySpecificService.SAML_RESPONSE_ERROR)!=null){
            PEPSErrors pepsError=null;
            try {
                pepsError = PEPSErrors.valueOf(request.getParameter(CountrySpecificService.SAML_RESPONSE_ERROR));
            }catch(IllegalArgumentException iae){
                LOG.info("BUSINESS EXCEPTION : processing plugin response {}", iae.getMessage());
                LOG.debug("BUSINESS EXCEPTION : processing plugin response {}", iae);
                pepsError=PEPSErrors.INTERNAL_ERROR;
            }
            throw new InvalidParameterPEPSException( PEPSUtil.getConfig(pepsError.errorCode()), PEPSUtil.getConfig(pepsError.errorMessage()));
        }
        IPersonalAttributeList attributeList = specificCountry.extractSAMLResponse(request, storkSession);
        if(attributeList.isEmpty() && request.getAttribute(CountrySpecificService.SAML_RESPONSE_ERROR)!=null){
            PEPSErrors pepsError=null;
            try {
                pepsError = PEPSErrors.valueOf(request.getAttribute(CountrySpecificService.SAML_RESPONSE_ERROR).toString());
            }catch(IllegalArgumentException iae){
                LOG.info("BUSINESS EXCEPTION : processing plugin response {}", iae.getMessage());
                LOG.debug("BUSINESS EXCEPTION : processing plugin response {}", iae);
                pepsError=PEPSErrors.INTERNAL_ERROR;
            }
            throw new InvalidParameterPEPSException( PEPSUtil.getConfig(pepsError.errorCode()), PEPSUtil.getConfig(pepsError.errorMessage()));
        }
        return attributeList;
    }

    private ApplicationContext getApplicationContext(){
        return ApplicationContextProvider.getApplicationContext();
    }

    private CountrySpecificService getCountryHandler(HttpServletRequest request){
        Map map = ApplicationContextProvider.getApplicationContext().getBeansOfType(CountrySpecificService.class);
        for( Object value: map.values()){
            CountrySpecificService currentCountryService=(CountrySpecificService)value;
            if(currentCountryService.isCountryResponse(request)) {
                String isoCode = currentCountryService.getIsoCode();
                if(getSpepsUtil()!=null && getSpepsUtil().getConfigs()!=null){
                    String activationParameter=getSpepsUtil().getConfigs().getProperty("active.module.plugin"+isoCode);
                    if (activationParameter != null && !Boolean.valueOf(activationParameter)) {
                        String msg = "ERROR : Integration module "+isoCode+" is inactive by configuration setting";
                        LOG.warn(msg);
                        return null;
                    }
                }

                return currentCountryService;
            }
        }
        return null;
    }
    public AUSPEPSUtil getSpepsUtil() {
        return spepsUtil;
    }

    public void setSpepsUtil(AUSPEPSUtil spepsUtil) {
        this.spepsUtil = spepsUtil;
    }


}
