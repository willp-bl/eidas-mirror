package eu.stork.peps.auth.engine.core.eidas;


public enum EidasAttributesTypes {
    NATURAL_PERSON_MANDATORY(true),
    NATURAL_PERSON_OPTIONAL(false),
    LEGAL_PERSON_MANDATORY(true),
    LEGAL_PERSON_OPTIONAL(false),
    ;
    public static final String NATURAL_PERSON="naturalperson";
    public static final String LEGAL_PERSON="legalperson";
    static{
        NATURAL_PERSON_MANDATORY.personType=NATURAL_PERSON;
        NATURAL_PERSON_OPTIONAL.personType=NATURAL_PERSON;
        LEGAL_PERSON_MANDATORY.personType=LEGAL_PERSON;
        LEGAL_PERSON_OPTIONAL.personType=LEGAL_PERSON;
    }

    private String personType;
    private boolean mandatory;
    private EidasAttributesTypes(boolean mandatory){
        this.mandatory=mandatory;
    }
}
