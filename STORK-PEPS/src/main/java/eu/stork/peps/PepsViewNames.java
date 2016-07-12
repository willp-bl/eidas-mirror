package eu.stork.peps;

/**
 * See "Effective Java edition 2 (Joshua Bloch - Addison Wesley 20012)" item 30
 */
public enum PepsViewNames {
    SPEPS_COLLEAGUE_REQUEST_REDIRECT("/colleagueRequestRedirect.jsp"),
    SPEPS_COLLEAGUE_RESPONSE_REDIRECT("/colleagueResponseRedirect.jsp"),
    SPEPS_COUNTRY_SELECTOR("/countrySelector.jsp"),
    SPEPS_PRESENT_CONSENT("/presentConsent.jsp"),
    SPEPS_REDIRECT("/spepsRedirect.jsp"),
    CPEPS_AP_REDIRECT("/apRedirect.jsp"),
    CPEPS_CITIZEN_CONSENT("/citizenConsent.jsp"),
    CPEPS_IDP_REDIRECT("/idpRedirect.jsp"),
    CPEPS_SIG_CREATOR_MODULE("/sigCreatorModuleRedirect.jsp"),
    CPEPS_PRESENT_CONSENT("/presentConsent.jsp"),
    INTERNAL_ERROR("/internalError.jsp"),
    INTERCEPTOR_ERROR("/interceptorError.jsp"),
    ERROR("/error.jsp"),
    PRESENT_ERROR("/presentError.jsp"),
    MISSING_PARAMETER("/missingParameter.jsp"),
    CITIZEN_AUTHENTICATION("/CitizenAuthentication"),
    AP_SELECTOR("specific.ap.selector"),
    CPEPS_NO_CONSENT("/CitizenConsent"),
    SERVLET_PATH_SERVICE_PROVIDER ( "/ServiceProvider"),
    SERVLET_PATH_BKU_ANMELDUNG( "/Bku-anmeldung"),
    SUBMIT_ERROR("/presentSamlResponseError.jsp"),
    SPEPS_COUNTRY_FRAMING("/countryFraming.jsp"),
    ;


    /**
     * constant name.
     */
    private String name;

    /**
     * Constructor
     * @param name name of the bean
     */
    PepsViewNames(final String name){
        this.name = name;
    }

    @Override
    public String toString() {
        return name;

    }
}
