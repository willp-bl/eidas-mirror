package eu.stork.peps.auth.cpeps;

import eu.stork.peps.auth.commons.*;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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
    public void prepareRequest(HttpServletRequest req, STORKAuthnRequest authData){
        //nothing to do while inactive
    }
    public String getRedirectUrl(HttpServletRequest req){
        return "";
    }
    public boolean isCountryResponse(HttpServletRequest req){
        return allowRequestThroughFilter(req);
    }
    public IPersonalAttributeList extractSAMLResponse(HttpServletRequest req,IStorkSession session){
        return new PersonalAttributeList();
    }

    public boolean isResponseReady(HttpServletRequest req,IStorkSession session){
        return false;
    }

    public void performNextStep(ServletContext ctx, HttpServletRequest req,HttpServletResponse response, IStorkSession session){
        //nothing to do while inactive
    }

}
