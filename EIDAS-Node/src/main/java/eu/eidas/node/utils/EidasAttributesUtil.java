package eu.eidas.node.utils;

import eu.eidas.auth.commons.IPersonalAttributeList;
import eu.eidas.auth.commons.PersonalAttribute;
import eu.eidas.auth.engine.core.validator.eidas.EIDASAttributes;

import java.util.HashSet;
import java.util.Set;

public class EidasAttributesUtil {
    public static final String EIDAS_NATURALPERSON_PREFIX=EIDASAttributes.ATTRIBUTE_NAME_PREFIX_NATURAL_PERSON;
    public static final String EIDAS_LEGALPERSON_PREFIX=EIDASAttributes.ATTRIBUTE_NAME_PREFIX_LEGAL_PERSON;
    public static final String EIDAS_NATURALPERSON_IDENTIFIER=EIDASAttributes.ATTRIBUTE_PERSONIDENTIFIER;
    public static final String EIDAS_LEGALPERSON_IDENTIFIER=EIDASAttributes.ATTRIBUTE_LEGALIDENTIFIER;
    private static final Set<String> EIDAS_NATURALPERSON_MANDATORY=new HashSet<String>();
    private static final Set<String> EIDAS_LEGALPERSON_MANDATORY=new HashSet<String>();
    static {
        EIDAS_NATURALPERSON_MANDATORY.add(EIDASAttributes.ATTRIBUTE_GIVENNAME);
        EIDAS_NATURALPERSON_MANDATORY.add(EIDASAttributes.ATTRIBUTE_FIRSTNAME);
        EIDAS_NATURALPERSON_MANDATORY.add(EIDASAttributes.ATTRIBUTE_DATEOFBIRTH);
        EIDAS_NATURALPERSON_MANDATORY.add(EIDASAttributes.ATTRIBUTE_PERSONIDENTIFIER);
        EIDAS_LEGALPERSON_MANDATORY.add(EIDASAttributes.ATTRIBUTE_LEGALNAME);
        EIDAS_LEGALPERSON_MANDATORY.add(EIDAS_LEGALPERSON_IDENTIFIER);
    }

    /**
     * check whether the attribute list contains at least one of the mandatory eIDAS attribute set (either for a
     * natural [person or for a legal person)
     * @param attributeList
     */
    public static boolean checkMandatoryAttributeSets(IPersonalAttributeList attributeList){
        boolean naturalPerson=false, legalPerson=false;
        if(attributeList==null){
            return false;
        }
        for(PersonalAttribute pa:attributeList){
            if(!naturalPerson && pa.getFullName()!=null && pa.getFullName().startsWith(EIDAS_NATURALPERSON_PREFIX)){
                naturalPerson=true;
            }
            if(!legalPerson && pa.getFullName()!=null && pa.getFullName().startsWith(EIDAS_LEGALPERSON_PREFIX)){
                legalPerson=true;
            }
        }
        int countNaturalMandatoryAttributes=0;
        if(naturalPerson){
            for(PersonalAttribute pa:attributeList){
                if(EIDAS_NATURALPERSON_MANDATORY.contains(pa.getFullName()) ){
                    pa.setIsRequired(true);
                    countNaturalMandatoryAttributes++;
                }
            }
        }
        int countLegalMandatoryAttributes=0;
        if(legalPerson){
            for(PersonalAttribute pa:attributeList){
                if(EIDAS_LEGALPERSON_MANDATORY.contains(pa.getFullName()) ){
                    pa.setIsRequired(true);
                    countLegalMandatoryAttributes++;
                }
            }
        }
        if(naturalPerson && countNaturalMandatoryAttributes!=EIDAS_NATURALPERSON_MANDATORY.size() ||
                legalPerson && countLegalMandatoryAttributes!=EIDAS_LEGALPERSON_MANDATORY.size()   ){
            return false;
        }
        return true;
    }

    public static String getUserFriendlyLoa(final String requestLoa){
        if (requestLoa != null) {
            int lastIndex = requestLoa.lastIndexOf('/');
            if (lastIndex > 0) {
                return requestLoa.substring(lastIndex + 1);
            } else {
                return requestLoa;
            }
        }
        return null;
    }

}
