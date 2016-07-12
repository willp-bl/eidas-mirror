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
package eu.eidas.node.auth.connector;

import java.nio.charset.Charset;
import java.util.List;
import java.util.Map;

import eu.eidas.auth.commons.*;
import eu.eidas.auth.commons.exceptions.InvalidParameterEIDASException;
import eu.eidas.auth.commons.exceptions.InvalidSessionEIDASException;
import eu.eidas.auth.commons.exceptions.EidasNodeException;
import eu.eidas.auth.engine.core.SAMLExtensionFormat;
import eu.eidas.auth.engine.core.eidas.SPType;
import eu.eidas.node.ApplicationContextProvider;
import eu.eidas.node.utils.EidasAttributesUtil;
import eu.eidas.node.utils.EidasNodeValidationUtil;

import org.apache.commons.lang.CharEncoding;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * The AUCONNECTOR class serves as the middle-man in the communications between the
 * Service Provider and the eIDAS ProxyService. It is responsible for handling the requests
 * coming from the Service Provider and forward them to the eIDAS ProxyService, and
 * vice-versa.
 *
 * @see ICONNECTORService
 */
public final class AUCONNECTOR implements ICONNECTORService{

    /**
     * Logger object.
     */
    private static final Logger LOG = LoggerFactory.getLogger(AUCONNECTOR.class.getName());
    /**
     * Service for country related operations.
     */
    private ICONNECTORCountrySelectorService countryService;

    /**
     * Service for SAML related operations.
     */
    private ICONNECTORSAMLService samlService;

    /**
     * Service for translation related operations.
     */
    private ICONNECTORTranslatorService transService;

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
     * Connector configuration.
     */
    private AUCONNECTORUtil connectorUtil;

    /**
     * {@inheritDoc}
     */
    public byte[] processCountrySelector(final Map<String, String> parameters) {

        // validates if a SP has permission to access a determined attribute
        final EIDASAuthnRequest authData =
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
    public EIDASAuthnRequest getAuthenticationRequest(
            final Map<String, String> parameters, final IEIDASSession session) {

        LOG.trace("Getting SAML Token");
        final byte[] spSamlToken =
                samlService.getSAMLToken(parameters,
                        EIDASErrors.SPROVIDER_SELECTOR_INVALID_SAML.name(), true);

        // validates the SAML Token
        EIDASAuthnRequest authData =
                samlService.processAuthenticationRequest(spSamlToken, parameters);
        final String relayStateCons = EIDASParameters.RELAY_STATE.toString();
        if (parameters.containsKey(relayStateCons)) {
            LOG.trace("Saving relay state.");
            session.put(relayStateCons, parameters.get(relayStateCons));
        }
        session.put(EIDASParameters.SP_URL.toString(), authData.getAssertionConsumerServiceURL());
        session.put(EIDASParameters.ERROR_REDIRECT_URL.toString(), authData.getAssertionConsumerServiceURL());
        session.put(EIDASParameters.SAML_IN_RESPONSE_TO.toString(), authData.getSamlId());

        LOG.debug("== SESSION : AUCONNECTOR.getAuthenticationRequest Called, size is " + session.size());
        if(connectorUtil!=null && Boolean.valueOf(connectorUtil.getConfigs().getProperty(EIDASParameters.VALIDATE_BINDING.toString()))) {
            EidasNodeValidationUtil.validateBinding(authData, parameters.get(EIDASParameters.HTTP_METHOD.toString()), EIDASErrors.SPROVIDER_SELECTOR_INVALID_SAML);
        }

        if(connectorUtil!=null && SAMLExtensionFormat.EIDAS10.getName().equalsIgnoreCase(authData.getMessageFormatName())){
            prepareEidasRequest(authData, parameters);
        }else {
            authData.setAssertionConsumerServiceURL(parameters.get(EIDASParameters.ASSERTION_CONSUMER_S_URL.toString()));
        }

        // normalize attributes to the supported format
        final IPersonalAttributeList pal =
                transService.normaliseAttributeNamesToFormat(authData
                        .getPersonalAttributeList());
        authData.setPersonalAttributeList(pal);

        // generate SAML Token
        authData = samlService.generateServiceAuthnRequest(authData);
        session.put(EIDASParameters.AUTH_REQUEST.toString(), authData);

        final byte[] samlToken = authData.getTokenSaml();
        authData.setTokenSaml(this.sendRedirect(samlToken).getBytes(Charset.forName("UTF-8")));

        final String remoteAddrCons = EIDASParameters.REMOTE_ADDR.toString();
        session.put(remoteAddrCons, parameters.get(remoteAddrCons));
        LOG.debug("== SESSION : AUCONNECTOR.getAuthenticationRequest Called, size is " + session.size());

        return authData;
    }

    private void prepareEidasRequest(final EIDASAuthnRequest authData,final Map<String, String> parameters){
        if(connectorUtil!=null && !Boolean.parseBoolean(connectorUtil.getConfigs().getProperty(EIDASValues.DISABLE_CHECK_MANDATORY_ATTRIBUTES.toString())) &&
            !EidasAttributesUtil.checkMandatoryAttributeSets(authData.getPersonalAttributeList())){
            LOG.error("BUSINESS EXCEPTION : incomplete mandatory set");
            throw new EidasNodeException(EIDASUtil.getConfig(EIDASErrors.EIDAS_MANDATORY_ATTRIBUTES.errorCode()), EIDASUtil.getConfig(EIDASErrors.EIDAS_MANDATORY_ATTRIBUTES.errorMessage()));
        }
        LOG.trace("do not fill in the assertion url");
        authData.setAssertionConsumerServiceURL(null);
        authData.setBinding(null);
        samlService.filterServiceSupportedAttrs(authData, parameters);
        if(!StringUtils.isEmpty(authData.getSPType()) && connectorUtil!=null && connectorUtil.getConfigs().containsKey(EIDASValues.EIDAS_SPTYPE.toString()) &&
                !connectorUtil.getConfigs().getProperty(EIDASValues.EIDAS_SPTYPE.toString()).equalsIgnoreCase(authData.getSPType())   ){
            LOG.error("BUSINESS EXCEPTION : SPType "+authData.getSPType() +"is not supported ");
            throw new EidasNodeException(EIDASUtil.getConfig(EIDASErrors.CONNECTOR_INVALID_SPTYPE.errorCode()), EIDASUtil.getConfig(EIDASErrors.CONNECTOR_INVALID_SPTYPE.errorMessage()));
        }
        if(connectorUtil!=null && !StringUtils.isEmpty(connectorUtil.getConfigs().getProperty(EIDASValues.EIDAS_SPTYPE.toString()))){
            //only the SPType in the connector's metadata will remain active
            authData.setSPType(null);
        }else if(StringUtils.isEmpty(authData.getSPType())){
            authData.setSPType(SPType.DEFAULT_VALUE);
        }

    }
    /**
     * {@inheritDoc}
     */
    public EIDASAuthnRequest getAuthenticationResponse(
            final Map<String, String> parameters, final IEIDASSession session) {

        final String authReqCons = EIDASParameters.AUTH_REQUEST.toString();
        final String inRespCons = EIDASParameters.SAML_IN_RESPONSE_TO.toString();


        if (session.isEmpty() || session.get(authReqCons) == null
                || session.get(inRespCons) == null) {
            LOG.info("BUSINESS EXCEPTION : Session is missing or invalid");

            throw new InvalidSessionEIDASException(
                    EIDASUtil.getConfig(EIDASErrors.INVALID_SESSION.errorCode()),
                    EIDASUtil.getConfig(EIDASErrors.INVALID_SESSION.errorMessage()));
        }

        LOG.trace("Getting SAML Token");
        final byte[] samlToken =
                samlService.getSAMLToken(parameters,
                        EIDASErrors.COLLEAGUE_RESP_INVALID_SAML.name(), false);

        // validates SAML Token
        EIDASAuthnRequest authData =
                (EIDASAuthnRequest) session.get(EIDASParameters.AUTH_REQUEST.toString());

        final String ipUserAddress =
                (String) session.get(EIDASParameters.REMOTE_ADDR.toString());
        final EIDASAuthnRequest spAuthData = new EIDASAuthnRequest();
        spAuthData.setAssertionConsumerServiceURL((String) session
                .get(EIDASParameters.SP_URL.toString()));
        spAuthData.setSamlId((String) session.get(inRespCons));
        spAuthData.setIssuer(authData.getIssuer());
        spAuthData.setMessageFormatName(authData.getMessageFormatName());
        spAuthData.setEidasNameidFormat(authData.getEidasNameidFormat());
        authData =
                samlService.processAuthenticationResponse(samlToken, authData,
                        spAuthData, ipUserAddress);

        // normalizes attributes from supported format
        final IPersonalAttributeList pal =
                transService.normaliseAttributeNamesFromFormat(authData
                        .getPersonalAttributeList());
        if(connectorUtil!=null && !Boolean.parseBoolean(connectorUtil.getConfigs().getProperty(EIDASValues.DISABLE_CHECK_MANDATORY_ATTRIBUTES.toString())) &&
            !EidasAttributesUtil.checkMandatoryAttributeSets(pal)){
            throw new EidasNodeException(EIDASUtil.getConfig(EIDASErrors.EIDAS_MANDATORY_ATTRIBUTES.errorCode()), EIDASUtil.getConfig(EIDASErrors.EIDAS_MANDATORY_ATTRIBUTES.errorMessage()));
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
        return EIDASUtil.encodeSAMLToken(samlToken);
    }

    /**
     * Setter for countryService.
     *
     * @param theCountryService The countryService to set.
     * @see ICONNECTORCountrySelectorService
     */
    public void setCountryService(
            final ICONNECTORCountrySelectorService theCountryService) {

        this.countryService = theCountryService;
    }

    /**
     * Getter for countryService.
     *
     * @return The countryService value.
     * @see ICONNECTORCountrySelectorService
     */
    public ICONNECTORCountrySelectorService getCountryService() {
        return countryService;
    }

    /**
     * Setter for samlService.
     *
     * @param theSamlService The samlService to set.
     * @see ICONNECTORSAMLService
     */
    public void setSamlService(final ICONNECTORSAMLService theSamlService) {
        this.samlService = theSamlService;
    }

    /**
     * Getter for samlService.
     *
     * @return The samlService value.
     * @see ICONNECTORSAMLService
     */
    public ICONNECTORSAMLService getSamlService() {
        return samlService;
    }

    /**
     * Setter for transService.
     *
     * @param nTransService The new transService value.
     * @see ICONNECTORTranslatorService
     */
    public void setTransService(final ICONNECTORTranslatorService nTransService) {
        this.transService = nTransService;
    }

    /**
     * Getter for transService.
     *
     * @return The transService value.
     * @see ICONNECTORTranslatorService
     */
    public ICONNECTORTranslatorService getTransService() {
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
     * @param eidasSession
     * @param parameters
     * @return the plugin response, which can be either the final response or a redirection to the next page (depends on the plugin)
     */
    public String processPluginResponse(final HttpServletRequest request, final HttpServletResponse response, final ServletContext context, final IEIDASSession eidasSession, final Map<String, String> parameters){
        CountrySpecificService specificCountry= getCountryHandler(request);
        if(specificCountry==null) {
            return null;
        }
        String sAMLResponse=null;
        if(specificCountry.isResponseReady(request,eidasSession)) {
            ICONNECTORSAMLService localSamlService = getApplicationContext().getBean(ICONNECTORSAMLService.class);
            final EIDASAuthnRequest authData = (EIDASAuthnRequest) eidasSession.get(EIDASParameters.AUTH_REQUEST.toString());
            final String spReqID = (String)eidasSession.get(EIDASParameters.SAML_IN_RESPONSE_TO.toString());
            IPersonalAttributeList attributeList = getPluginAttributeList(request, eidasSession, specificCountry);
            if(authData != null) {
                authData.setPersonalAttributeList(attributeList);
            }
            if(!attributeList.isEmpty()) {
                String authDataOriginalID=authData.getSamlId();
                authData.setAssertionConsumerServiceURL((String) eidasSession
                        .get(EIDASParameters.SP_URL.toString()));
                if(spReqID!=null) {
                    authData.setSamlId(spReqID);
                }
                byte[] authResponse = localSamlService.generateAuthenticationResponse(authData, parameters.get(EIDASParameters.REMOTE_ADDR.toString()));
                sAMLResponse = new String(EIDASUtil.encodeSAMLToken(authResponse).getBytes(Charset.forName(CharEncoding.UTF_8)), Charset.forName(CharEncoding.UTF_8));
                authData.setSamlId(authDataOriginalID);
            }
            eidasSession.clear();
            if (authData != null) {
                samlService.checkMandatoryAttributes(authData, parameters.get(EIDASParameters.REMOTE_ADDR.toString()));
            }
        }else{
            //redirection may needed (there is an intermediary step)
            specificCountry.performNextStep(context, request, response, eidasSession);
        }
        return sAMLResponse;

    }

    private IPersonalAttributeList getPluginAttributeList(final HttpServletRequest request, final IEIDASSession eidasSession,CountrySpecificService specificCountry){
        if(request.getParameter(CountrySpecificService.SAML_RESPONSE_ERROR)!=null){
            EIDASErrors eidasError=null;
            try {
                eidasError = EIDASErrors.valueOf(request.getParameter(CountrySpecificService.SAML_RESPONSE_ERROR));
            }catch(IllegalArgumentException iae){
                LOG.info("BUSINESS EXCEPTION : processing plugin response {}", iae.getMessage());
                LOG.debug("BUSINESS EXCEPTION : processing plugin response {}", iae);
                eidasError=EIDASErrors.INTERNAL_ERROR;
            }
            throw new InvalidParameterEIDASException( EIDASUtil.getConfig(eidasError.errorCode()), EIDASUtil.getConfig(eidasError.errorMessage()));
        }
        IPersonalAttributeList attributeList = specificCountry.extractSAMLResponse(request, eidasSession);
        if(attributeList.isEmpty() && request.getAttribute(CountrySpecificService.SAML_RESPONSE_ERROR)!=null){
            EIDASErrors eidasError=null;
            try {
                eidasError = EIDASErrors.valueOf(request.getAttribute(CountrySpecificService.SAML_RESPONSE_ERROR).toString());
            }catch(IllegalArgumentException iae){
                LOG.info("BUSINESS EXCEPTION : processing plugin response {}", iae.getMessage());
                LOG.debug("BUSINESS EXCEPTION : processing plugin response {}", iae);
                eidasError=EIDASErrors.INTERNAL_ERROR;
            }
            throw new InvalidParameterEIDASException( EIDASUtil.getConfig(eidasError.errorCode()), EIDASUtil.getConfig(eidasError.errorMessage()));
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
                if(getConnectorUtil()!=null && getConnectorUtil().getConfigs()!=null){
                    String activationParameter=getConnectorUtil().getConfigs().getProperty("active.module.plugin"+isoCode);
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
    public AUCONNECTORUtil getConnectorUtil() {
        return connectorUtil;
    }

    public void setConnectorUtil(AUCONNECTORUtil connectorUtil) {
        this.connectorUtil = connectorUtil;
    }


}
