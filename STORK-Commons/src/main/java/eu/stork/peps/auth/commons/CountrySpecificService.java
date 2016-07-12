package eu.stork.peps.auth.commons;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * handler for specific actions for a country
 */
public abstract class CountrySpecificService {
    private boolean active=false;
    public static final String SAML_RESPONSE_ERROR="SAML_RESPONSE_ERROR";
    public CountrySpecificService() {
    }

    /**
     *
     * @return the ISO code of the country to be handled by this specific service
     */
    public abstract String getIsoCode();

    /**
     *
     * @param req
     * @param authData
     * enrich the request with parameters needed by the country web component (included in peps)
     */
    public abstract void prepareRequest(HttpServletRequest req, STORKAuthnRequest authData);

    /**
     *
     * @param req
     * @return the ursl of the country's web component
     */
    public abstract String getRedirectUrl(HttpServletRequest req);

    /**
     *
     * @param req
     * @return true when the current req contains a response belonging to the current country
     */
    public abstract boolean isCountryResponse(HttpServletRequest req);

    /**
     *
     * @param req
     * @return true if the request should be allowed through the security filters
     */
    public boolean allowRequestThroughFilter(HttpServletRequest req){
        String country=req.getParameter("country");
        return country!=null && country.equalsIgnoreCase(getIsoCode());
    }

    /**
     *
     * @param req
     * @param session
     * @return the list of attributes (with values) retrieved from the response
     */
    public abstract IPersonalAttributeList extractSAMLResponse(HttpServletRequest req,IStorkSession session);

    public abstract boolean isResponseReady(HttpServletRequest req,IStorkSession session);

    public abstract void performNextStep(ServletContext ctx, HttpServletRequest req,HttpServletResponse response, IStorkSession session);

    public final boolean isActive(){
        return active;
    }
    public final void setActive(boolean activeArg){
        this.active= activeArg;
    }
}
