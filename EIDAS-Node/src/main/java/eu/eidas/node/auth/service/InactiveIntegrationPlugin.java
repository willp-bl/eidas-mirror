package eu.eidas.node.auth.service;

import javax.servlet.http.HttpServletRequest;

import eu.eidas.auth.commons.CountrySpecificService;
import eu.eidas.auth.commons.protocol.IAuthenticationRequest;

/**
 * acts as an inactive plugin when a country has a plugin configured (and active), but the actual plugin was not loaded
 * (eg missing jar)
 */
public class InactiveIntegrationPlugin extends CountrySpecificService{
    String isoCode=null;
    public InactiveIntegrationPlugin(String isoCode){
        this.isoCode=isoCode;
        setActive(false);
    }
    public String getIsoCode(){
        return isoCode;
    }
    public void prepareRequest(HttpServletRequest req, IAuthenticationRequest authData){
        //nothing to do while inactive
    }
    public String getRedirectUrl(HttpServletRequest req){
        return "";
    }
    public boolean isCountryResponse(HttpServletRequest req){
        return allowRequestThroughFilter(req);
    }

}
