package eu.eidas.auth.engine.core.eidas;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public enum EidasAttributesTypes {

    NATURAL_PERSON_MANDATORY(true),
    NATURAL_PERSON_OPTIONAL(false),
    LEGAL_PERSON_MANDATORY(true),
    LEGAL_PERSON_OPTIONAL(false),
    ;

    private static final Logger LOG = LoggerFactory.getLogger(EidasExtensionProcessor.class.getName());

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
    public static EidasAttributesTypes dynamicFromString(String type){
        if(NATURAL_PERSON.equalsIgnoreCase(type)){
            return NATURAL_PERSON_OPTIONAL;
        }else if(LEGAL_PERSON.equalsIgnoreCase(type)){
            return LEGAL_PERSON_OPTIONAL;
        }
        LOG.error("invalid value for attribute type found in the config: "+type);
        return null;
    }
}
