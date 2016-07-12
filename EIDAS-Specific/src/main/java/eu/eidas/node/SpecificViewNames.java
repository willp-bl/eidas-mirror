package eu.eidas.node;

import javax.annotation.Nonnull;

public enum SpecificViewNames {

    IDP_RESPONSE("/IdpResponse"),

    EXTERNAL_SIG_MODULE_REDIRECT("/sigCreatorModuleRedirect.jsp"),

    IDP_REDIRECT("/idpRedirect.jsp"),

    COLLEAGUE_RESPONSE_REDIRECT("/colleagueResponseRedirect.jsp"),

    //
    ;

    /**
     * constant name.
     */
    @Nonnull
    private final transient String name;

    /**
     * Constructor
     *
     * @param name name of the bean
     */
    SpecificViewNames(@Nonnull String name) {
        this.name = name;
    }

    @Nonnull
    @Override
    public String toString() {
        return name;

    }
}
