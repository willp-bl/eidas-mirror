package eu.eidas.node.connector;

import eu.eidas.auth.commons.*;
import eu.eidas.auth.commons.exceptions.EIDASServiceException;
import eu.eidas.node.ApplicationContextProvider;
import eu.eidas.node.NodeBeanNames;
import eu.eidas.node.NodeViewNames;
import eu.eidas.node.utils.CountrySpecificUtil;
import eu.eidas.node.utils.PropertiesUtil;
import eu.eidas.node.utils.SessionHolder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Map;

public class ServiceProviderServlet extends AbstractConnectorServlet {

    private static final Logger LOG = LoggerFactory.getLogger(ServiceProviderServlet.class.getName());

    private static final long serialVersionUID = 2037358134080320372L;

    @Override
    protected Logger getLogger() {
        return LOG;
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        if(acceptsHttpRedirect()) {
            doPost(request, response);
        }else {
            LOG.warn("BUSINESS EXCEPTION : redirect binding is not allowed");
        }
    }
    /**
     * Post method
     * @param request
     * @param response
     * @throws ServletException
     * @throws IOException
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Prevent cookies from being accessed through client-side script WITH renew of session.
        setHTTPOnlyHeaderToSession(true, request, response);
        SessionHolder.setId(request.getSession());
        request.getSession().setAttribute(EIDASParameters.SAML_PHASE.toString(), EIDASValues.SP_REQUEST);
        request.getSession().setAttribute(EIDASParameters.EIDAS_CONNECTOR_SESSION.toString(), Boolean.TRUE);

        // Obtaining the assertion consumer url from SPRING context
        ConnectorControllerService controllerService= (ConnectorControllerService) getApplicationContext().getBean(NodeBeanNames.EIDAS_CONNECTOR_CONTROLLER.toString());
        LOG.trace(controllerService.toString());
        // Obtains the parameters from httpRequest
        final Map<String, String> parameters = getHttpRequestParameters(request);

        // Validating the HTTP Parameter sAMLRequest.
        final String samlRequest = parameters.get(EIDASParameters.SAML_REQUEST.toString());
        EIDASUtil.validateParameter(this.getClass().getCanonicalName(), EIDASParameters.SAML_REQUEST.toString(), samlRequest, EIDASErrors.SPROVIDER_SELECTOR_INVALID_SAML);

        // Validating the optional HTTP Parameter relayState.
        final String relayState = parameters.get(EIDASParameters.RELAY_STATE.toString());
        if (relayState != null) { // RelayState's HTTP Parameter is optional!
            EIDASUtil.validateParameter(this.getClass().getCanonicalName(), EIDASParameters.RELAY_STATE.toString(), relayState, EIDASErrors.SPROVIDER_SELECTOR_INVALID_RELAY_STATE);
        }

        // Validating injected parameter.
        EIDASUtil.validateParameter(this.getClass().getCanonicalName(), EIDASErrors.CONNECTOR_REDIRECT_URL.toString(), controllerService.getAssertionConsUrl());
        parameters.put(EIDASParameters.ASSERTION_CONSUMER_S_URL.toString(), encodeURL(controllerService.getAssertionConsUrl(), response));
        parameters.put(EIDASParameters.HTTP_METHOD.toString(), request.getMethod());


        // Validates the origin of the request, normalizes data, creates, sign and send an SAML.
        final EIDASAuthnRequest authData = controllerService.getConnectorService().getAuthenticationRequest(parameters, controllerService.getSession());
        request.getSession().setAttribute(EIDASParameters.SAML_IN_RESPONSE_TO.toString(), authData.getSamlId());
        request.getSession().setAttribute(EIDASParameters.ISSUER.toString(), authData.getIssuer());

        //the request is valid, so normally for any error raised from here we have to send back a saml response

        PropertiesUtil.checkConnectorActive();

        // push the samlRequest in the distributed hashMap - Sets the internal ProxyService URL variable to redirect the Citizen to the ProxyService
        final String serviceUrl = authData.getDestination();
        EIDASUtil.validateParameter(this.getClass().getCanonicalName(), EIDASErrors.SERVICE_REDIRECT_URL.toString(), serviceUrl);
        LOG.debug("Redirecting to serviceUrl: " + serviceUrl);
        // Validates the SAML TOKEN
        final String samlRequestTokenSaml= new String(authData.getTokenSaml(), Charset.forName("UTF-8"));
        EIDASUtil.validateParameter(this.getClass().getCanonicalName(), EIDASParameters.SAML_REQUEST.toString(), samlRequestTokenSaml, EIDASErrors.SPROVIDER_SELECTOR_ERROR_CREATE_SAML);
        LOG.debug("sessionId is on cookies () or fromURL ", request.isRequestedSessionIdFromCookie(), request.isRequestedSessionIdFromURL());
        if(acceptsHttpRedirect() && request.getMethod()==EIDASAuthnRequest.BINDING_REDIRECT) {
            request.setAttribute(EIDASParameters.BINDING.toString(), EIDASAuthnRequest.BINDING_REDIRECT);
        }else {
            request.setAttribute(EIDASParameters.BINDING.toString(), EIDASAuthnRequest.BINDING_POST);
        }
        request.setAttribute(NodeBeanNames.EIDAS_SERVICE_URL.toString(), encodeURL(serviceUrl, response)); // // Correct URl redirect cookie implementation
        request.setAttribute(NodeBeanNames.SAML_REQUEST.toString(), samlRequestTokenSaml);
        request.setAttribute(NodeBeanNames.RELAY_STATE.toString(), relayState);
        // Redirecting where it should be
        prepareCountryData(request, authData);
        RequestDispatcher dispatcher = request.getRequestDispatcher(handleCountrySelection(authData.getCitizenCountryCode()/*, moaConfigData*/, request));

        request.getSession().setAttribute(EIDASParameters.SAML_PHASE.toString(), EIDASValues.EIDAS_CONNECTOR_REQUEST);
        SessionHolder.clear();

        dispatcher.forward(request, response);

    }

    /**
     * Retrieve the selected country from the request and set the value on the
     * authentication request.
     */
    private String handleCountrySelection(final String citizenCountry, HttpServletRequest request) throws ServletException{
        CountrySpecificUtil csu=ApplicationContextProvider.getApplicationContext().getBean(CountrySpecificUtil.class);
        CountrySpecificService specificCountry= csu.getCountryHandler(citizenCountry);
        if(specificCountry!=null) {
            if(!specificCountry.isActive()){
                throw new EIDASServiceException(null, EIDASUtil.getConfig(EIDASErrors.SP_COUNTRY_SELECTOR_INVALID.errorCode()), EIDASUtil.getConfig(EIDASErrors.SP_COUNTRY_SELECTOR_INVALID.errorMessage()));
            }
            return specificCountry.getRedirectUrl(request);
        }

        return NodeViewNames.EIDAS_CONNECTOR_COLLEAGUE_REQUEST_REDIRECT.toString();
    }
    private void prepareCountryData(HttpServletRequest request, EIDASAuthnRequest authData){
        CountrySpecificUtil csu=ApplicationContextProvider.getApplicationContext().getBean(CountrySpecificUtil.class);
        CountrySpecificService specificCountry=csu.getCountryHandler(authData.getCitizenCountryCode());
        if (specificCountry !=null && specificCountry.isActive()){
            specificCountry.prepareRequest(request, authData);
        }
    }

}
