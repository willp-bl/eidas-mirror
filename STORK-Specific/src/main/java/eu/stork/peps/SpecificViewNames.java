package eu.stork.peps;

public enum SpecificViewNames {
  AP_RESPONSE("/ApResponse"),
  IDP_RESPONSE("/IdpResponse"),
  AP_REDIRECT("/apRedirect.jsp"),
  EXTERNAL_SIG_MODULE_REDIRECT("/sigCreatorModuleRedirect.jsp"),
  IDP_REDIRECT("/idpRedirect.jsp");


    /**
     * constant name.
     */
    private String name;

    /**
     * Constructor
     * @param name name of the bean
     */
    SpecificViewNames(final String name){
        this.name = name;
    }

    @Override
    public String toString() {
        return name;

    }
}