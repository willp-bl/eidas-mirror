package eu.stork.peps.speps;

import eu.stork.peps.ApplicationContextProvider;
import eu.stork.peps.auth.commons.*;
import eu.stork.peps.PepsBeanNames;
import eu.stork.peps.PepsViewNames;
import eu.stork.peps.auth.commons.exceptions.CPEPSException;
import eu.stork.peps.utils.CountrySpecificUtil;
import eu.stork.peps.utils.PropertiesUtil;
import eu.stork.peps.utils.SessionHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Map;

public class ServiceProviderServlet extends AbstractSPepsServlet {

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
        request.getSession().setAttribute(PEPSParameters.SAML_PHASE.toString(), PEPSValues.SP_REQUEST);
        request.getSession().setAttribute(PEPSParameters.SPEPS_SESSION.toString(), Boolean.TRUE);

        // Obtaining the assertion consumer url from SPRING context
        SPepsControllerService controllerService= (SPepsControllerService) getApplicationContext().getBean(PepsBeanNames.S_PEPS_CONTROLLER.toString());
        LOG.trace(controllerService.toString());
        // Obtains the parameters from httpRequest
        final Map<String, String> parameters = getHttpRequestParameters(request);

        // Validating the HTTP Parameter sAMLRequest.
        final String samlRequest = parameters.get(PEPSParameters.SAML_REQUEST.toString());
        PEPSUtil.validateParameter(this.getClass().getCanonicalName(), PEPSParameters.SAML_REQUEST.toString(), samlRequest, PEPSErrors.SPROVIDER_SELECTOR_INVALID_SAML);

        // Validating the optional HTTP Parameter relayState.
        final String relayState = parameters.get(PEPSParameters.RELAY_STATE.toString());
        if (relayState != null) { // RelayState's HTTP Parameter is optional!
            PEPSUtil.validateParameter(this.getClass().getCanonicalName(), PEPSParameters.RELAY_STATE.toString(), relayState, PEPSErrors.SPROVIDER_SELECTOR_INVALID_RELAY_STATE);
        }

        // Validating injected parameter.
        PEPSUtil.validateParameter(this.getClass().getCanonicalName(), PEPSErrors.SPEPS_REDIRECT_URL.toString(), controllerService.getAssertionConsUrl());
        parameters.put(PEPSParameters.ASSERTION_CONSUMER_S_URL.toString(), encodeURL(controllerService.getAssertionConsUrl(), response));
        parameters.put(PEPSParameters.HTTP_METHOD.toString(), request.getMethod());


        // Validates the origin of the request, normalizes data, creates, sign and send an SAML.
        final STORKAuthnRequest authData = controllerService.getSpepsService().getAuthenticationRequest(parameters, controllerService.getSession());
        request.getSession().setAttribute(PEPSParameters.SAML_IN_RESPONSE_TO.toString(), authData.getSamlId());
        request.getSession().setAttribute(PEPSParameters.ISSUER.toString(), authData.getIssuer());

        //the request is valid, so normally for any error raised from here we have to send back a saml response

        PropertiesUtil.checkSPEPSActive();

        // push the samlRequest in the distributed hashMap - Sets the internal C-PEPS URL variable to redirect the Citizen to C-PEPS
        final String cPepsUrl = authData.getDestination();
        PEPSUtil.validateParameter(this.getClass().getCanonicalName(), PEPSErrors.CPEPS_REDIRECT_URL.toString(), cPepsUrl);
        LOG.debug("Redirecting to cPepsUrl: " + cPepsUrl);
        // Validates the SAML TOKEN
        final String samlRequestTokenSaml= new String(authData.getTokenSaml(), Charset.forName("UTF-8"));
        PEPSUtil.validateParameter(this.getClass().getCanonicalName(), PEPSParameters.SAML_REQUEST.toString(), samlRequestTokenSaml, PEPSErrors.SPROVIDER_SELECTOR_ERROR_CREATE_SAML);
        LOG.debug("sessionId is on cookies () or fromURL ", request.isRequestedSessionIdFromCookie(), request.isRequestedSessionIdFromURL());
        if(acceptsHttpRedirect() && request.getMethod()==STORKAuthnRequest.BINDING_REDIRECT) {
            request.setAttribute(PEPSParameters.BINDING.toString(), STORKAuthnRequest.BINDING_REDIRECT);
        }else {
            request.setAttribute(PEPSParameters.BINDING.toString(), STORKAuthnRequest.BINDING_POST);
        }
        request.setAttribute(PepsBeanNames.CPEPS_URL.toString(), encodeURL(cPepsUrl, response)); // // Correct URl redirect cookie implementation
        request.setAttribute(PepsBeanNames.SAML_REQUEST.toString(), samlRequestTokenSaml);
        request.setAttribute(PepsBeanNames.RELAY_STATE.toString(), relayState);
        // Redirecting where it should be
        prepareCountryData(request, authData);
        RequestDispatcher dispatcher = request.getRequestDispatcher(handleCountrySelection(authData.getCitizenCountryCode()/*, moaConfigData*/, request));

        request.getSession().setAttribute(PEPSParameters.SAML_PHASE.toString(), PEPSValues.SPEPS_REQUEST);
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
                throw new CPEPSException(null, PEPSUtil.getConfig(PEPSErrors.SP_COUNTRY_SELECTOR_INVALID.errorCode()), PEPSUtil.getConfig(PEPSErrors.SP_COUNTRY_SELECTOR_INVALID.errorMessage()));
            }
            return specificCountry.getRedirectUrl(request);
        }

        return PepsViewNames.SPEPS_COLLEAGUE_REQUEST_REDIRECT.toString();
    }
    private void prepareCountryData(HttpServletRequest request, STORKAuthnRequest authData){
        CountrySpecificUtil csu=ApplicationContextProvider.getApplicationContext().getBean(CountrySpecificUtil.class);
        CountrySpecificService specificCountry=csu.getCountryHandler(authData.getCitizenCountryCode());
        if (specificCountry !=null && specificCountry.isActive()){
            specificCountry.prepareRequest(request, authData);
        }
    }

}
