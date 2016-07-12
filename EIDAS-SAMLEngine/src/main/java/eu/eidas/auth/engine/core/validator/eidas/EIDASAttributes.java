/*
 * Licensed under the EUPL, Version 1.1 or – as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence");
 * You may not use this work except in compliance with the Licence. You may
 * obtain a copy of the Licence at:
 *
 * http://www.osor.eu/eupl/european-union-public-licence-eupl-v.1.1
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * Licence for the specific language governing permissions and limitations under
 * the Licence.
 */
package eu.eidas.auth.engine.core.validator.eidas;


import eu.eidas.auth.engine.core.eidas.EidasAttributesTypes;
import eu.eidas.auth.engine.core.eidas.EidasExtensionProcessor;

import java.util.*;


public final class EIDASAttributes {

    private EIDASAttributes(){
    }
    public final static String EIDAS10_NS = "urn:eu:stork:names:tc:STORK:1.0:assertion";
    public final static String EIDAS10_PREFIX = "stork";
    public final static String EIDASP10_NS = "urn:eu:stork:names:tc:STORK:1.0:protocol";
    public final static String EIDASP10_PREFIX = "storkp";
    public final static String TYPE_SUFFIX="Type";

    public final static String ATTRIBUTE_NAME_PREFIX_NATURAL_PERSON = "http://eidas.europa.eu/attributes/naturalperson/";
    public final static String ATTRIBUTE_NAME_PREFIX_LEGAL_PERSON = "http://eidas.europa.eu/attributes/legalperson/";

    public final static String ATTRIBUTE_NAME_SUFFIX_GIVENNAME = "CurrentFamilyName";
    public final static String ATTRIBUTE_GIVENNAME = ATTRIBUTE_NAME_PREFIX_NATURAL_PERSON + ATTRIBUTE_NAME_SUFFIX_GIVENNAME;

    public final static String ATTRIBUTE_NAME_SUFFIX_FIRSTNAME = "CurrentGivenName";
    public final static String ATTRIBUTE_FIRSTNAME = ATTRIBUTE_NAME_PREFIX_NATURAL_PERSON + ATTRIBUTE_NAME_SUFFIX_FIRSTNAME;

    public final static String ATTRIBUTE_NAME_SUFFIX_DATEOFBIRTH = "DateOfBirth";
    public final static String ATTRIBUTE_DATEOFBIRTH = ATTRIBUTE_NAME_PREFIX_NATURAL_PERSON + ATTRIBUTE_NAME_SUFFIX_DATEOFBIRTH;

    public final static String ATTRIBUTE_NAME_SUFFIX_PERSONIDENTIFIER = "PersonIdentifier";
    public final static String ATTRIBUTE_PERSONIDENTIFIER = ATTRIBUTE_NAME_PREFIX_NATURAL_PERSON + ATTRIBUTE_NAME_SUFFIX_PERSONIDENTIFIER;

    public final static String ATTRIBUTE_NAME_SUFFIX_BIRTHNAME = "BirthName";
    public final static String ATTRIBUTE_BIRTHNAME = ATTRIBUTE_NAME_PREFIX_NATURAL_PERSON + ATTRIBUTE_NAME_SUFFIX_BIRTHNAME;

    public final static String ATTRIBUTE_NAME_SUFFIX_CURRENTADDRESS = "CurrentAddress";
    public final static String ATTRIBUTE_CURRENTADDRESS = ATTRIBUTE_NAME_PREFIX_NATURAL_PERSON + ATTRIBUTE_NAME_SUFFIX_CURRENTADDRESS;

    public final static String ATTRIBUTE_NAME_SUFFIX_PLACEOFBIRTH = "PlaceOfBirth";
    public final static String ATTRIBUTE_PLACEOFBIRTH = ATTRIBUTE_NAME_PREFIX_NATURAL_PERSON + ATTRIBUTE_NAME_SUFFIX_PLACEOFBIRTH;

    public final static String ATTRIBUTE_NAME_SUFFIX_GENDER = "Gender";
    public final static String ATTRIBUTE_GENDER = ATTRIBUTE_NAME_PREFIX_NATURAL_PERSON + ATTRIBUTE_NAME_SUFFIX_GENDER;

    public final static String ATTRIBUTE_NAME_SUFFIX_LEGALIDENTIFIER = "LegalPersonIdentifier";
    public final static String ATTRIBUTE_LEGALIDENTIFIER = ATTRIBUTE_NAME_PREFIX_LEGAL_PERSON + ATTRIBUTE_NAME_SUFFIX_LEGALIDENTIFIER;

    public final static String ATTRIBUTE_NAME_SUFFIX_LEGALADDRESS = "LegalAddress";
    public final static String ATTRIBUTE_LEGALADDRESS = ATTRIBUTE_NAME_PREFIX_LEGAL_PERSON + ATTRIBUTE_NAME_SUFFIX_LEGALADDRESS;

    public final static String ATTRIBUTE_NAME_SUFFIX_LEGALNAME = "LegalName";
    public final static String ATTRIBUTE_LEGALNAME = ATTRIBUTE_NAME_PREFIX_LEGAL_PERSON + ATTRIBUTE_NAME_SUFFIX_LEGALNAME;

    public final static String ATTRIBUTE_NAME_SUFFIX_VATREGISTRATION = "VATRegistration";
    public final static String ATTRIBUTE_VATREGISTRATION = ATTRIBUTE_NAME_PREFIX_LEGAL_PERSON + ATTRIBUTE_NAME_SUFFIX_VATREGISTRATION;

    public final static String ATTRIBUTE_NAME_SUFFIX_TAXREFERENCE = "TaxReference";
    public final static String ATTRIBUTE_TAXREFERENCE = ATTRIBUTE_NAME_PREFIX_LEGAL_PERSON + ATTRIBUTE_NAME_SUFFIX_TAXREFERENCE;

    public final static String ATTRIBUTE_NAME_SUFFIX_BUSINESSCODE = "D-2012-17-EUIdentifier";
    public final static String ATTRIBUTE_BUSINESSCODE = ATTRIBUTE_NAME_PREFIX_LEGAL_PERSON + ATTRIBUTE_NAME_SUFFIX_BUSINESSCODE;

    public final static String ATTRIBUTE_NAME_SUFFIX_LEI = "LEI";
    public final static String ATTRIBUTE_LEI = ATTRIBUTE_NAME_PREFIX_LEGAL_PERSON + ATTRIBUTE_NAME_SUFFIX_LEI;

    public final static String ATTRIBUTE_NAME_SUFFIX_EORI = "EORI";
    public final static String ATTRIBUTE_EORI = ATTRIBUTE_NAME_PREFIX_LEGAL_PERSON + ATTRIBUTE_NAME_SUFFIX_EORI;

    public final static String ATTRIBUTE_NAME_SUFFIX_SEED = "SEED";
    public final static String ATTRIBUTE_SEED = ATTRIBUTE_NAME_PREFIX_LEGAL_PERSON + ATTRIBUTE_NAME_SUFFIX_SEED;

    public final static String ATTRIBUTE_NAME_SUFFIX_SIC = "SIC";
    public final static String ATTRIBUTE_SIC = ATTRIBUTE_NAME_PREFIX_LEGAL_PERSON + ATTRIBUTE_NAME_SUFFIX_SIC;

    /**
     *
     * @param fullAttrName
     * @return the type of the attribute named fullAttrName
     */
    public static final EidasAttributesTypes getAttributeType(String fullAttrName){
        EidasAttributesTypes type=ATTRIBUTES_TO_ATTRIBUTETYPE.get(fullAttrName);
        if(type==null){
            type = EidasExtensionProcessor.getDynamicAtributeType(fullAttrName);
        }
        return type;
    }

    /**
     * maps attribute names to their attribute type (either natural person or legal person, either mandatory or optional)
     */
    public final static Map<String, EidasAttributesTypes> ATTRIBUTES_TO_ATTRIBUTETYPE = Collections.unmodifiableMap(
            new HashMap<String, EidasAttributesTypes>(){
                {
                    put(ATTRIBUTE_GIVENNAME, EidasAttributesTypes.NATURAL_PERSON_MANDATORY);
                    put(ATTRIBUTE_FIRSTNAME, EidasAttributesTypes.NATURAL_PERSON_MANDATORY);
                    put(ATTRIBUTE_DATEOFBIRTH, EidasAttributesTypes.NATURAL_PERSON_MANDATORY);
                    put(ATTRIBUTE_PERSONIDENTIFIER, EidasAttributesTypes.NATURAL_PERSON_MANDATORY);
                    put(ATTRIBUTE_BIRTHNAME, EidasAttributesTypes.NATURAL_PERSON_OPTIONAL);
                    put(ATTRIBUTE_CURRENTADDRESS, EidasAttributesTypes.NATURAL_PERSON_OPTIONAL);
                    put(ATTRIBUTE_PLACEOFBIRTH, EidasAttributesTypes.NATURAL_PERSON_OPTIONAL);
                    put(ATTRIBUTE_GENDER, EidasAttributesTypes.NATURAL_PERSON_OPTIONAL);
                    put(ATTRIBUTE_LEGALIDENTIFIER, EidasAttributesTypes.LEGAL_PERSON_MANDATORY);
                    put(ATTRIBUTE_LEGALADDRESS, EidasAttributesTypes.LEGAL_PERSON_OPTIONAL);
                    put(ATTRIBUTE_LEGALNAME, EidasAttributesTypes.LEGAL_PERSON_MANDATORY);
                    put(ATTRIBUTE_VATREGISTRATION, EidasAttributesTypes.LEGAL_PERSON_OPTIONAL);
                    put(ATTRIBUTE_TAXREFERENCE, EidasAttributesTypes.LEGAL_PERSON_OPTIONAL);
                    put(ATTRIBUTE_BUSINESSCODE, EidasAttributesTypes.LEGAL_PERSON_OPTIONAL);
                    put(ATTRIBUTE_LEI, EidasAttributesTypes.LEGAL_PERSON_OPTIONAL);
                    put(ATTRIBUTE_EORI, EidasAttributesTypes.LEGAL_PERSON_OPTIONAL);
                    put(ATTRIBUTE_SEED, EidasAttributesTypes.LEGAL_PERSON_OPTIONAL);
                    put(ATTRIBUTE_SIC, EidasAttributesTypes.LEGAL_PERSON_OPTIONAL);
                }
            }
    );
    /**
     * maps attribute names to their shortnames
     */
    public final static  Map<String, String> ATTRIBUTES_TO_SHORTNAMES = Collections.unmodifiableMap(
            new HashMap<String, String>(){
                {
                    put(ATTRIBUTE_GIVENNAME, ATTRIBUTE_NAME_SUFFIX_GIVENNAME);
                    put(ATTRIBUTE_FIRSTNAME, ATTRIBUTE_NAME_SUFFIX_FIRSTNAME);
                    put(ATTRIBUTE_DATEOFBIRTH, ATTRIBUTE_NAME_SUFFIX_DATEOFBIRTH);
                    put(ATTRIBUTE_PERSONIDENTIFIER, ATTRIBUTE_NAME_SUFFIX_PERSONIDENTIFIER);
                    put(ATTRIBUTE_BIRTHNAME, ATTRIBUTE_NAME_SUFFIX_BIRTHNAME);
                    put(ATTRIBUTE_CURRENTADDRESS, ATTRIBUTE_NAME_SUFFIX_CURRENTADDRESS);
                    put(ATTRIBUTE_PLACEOFBIRTH, ATTRIBUTE_NAME_SUFFIX_PLACEOFBIRTH);
                    put(ATTRIBUTE_GENDER, ATTRIBUTE_NAME_SUFFIX_GENDER);
                    put(ATTRIBUTE_LEGALIDENTIFIER, ATTRIBUTE_NAME_SUFFIX_LEGALIDENTIFIER);
                    put(ATTRIBUTE_LEGALADDRESS, ATTRIBUTE_NAME_SUFFIX_LEGALADDRESS);
                    put(ATTRIBUTE_LEGALNAME, ATTRIBUTE_NAME_SUFFIX_LEGALNAME);
                    put(ATTRIBUTE_VATREGISTRATION,ATTRIBUTE_NAME_SUFFIX_VATREGISTRATION );
                    put(ATTRIBUTE_TAXREFERENCE, ATTRIBUTE_NAME_SUFFIX_TAXREFERENCE);
                    put(ATTRIBUTE_BUSINESSCODE, ATTRIBUTE_NAME_SUFFIX_BUSINESSCODE);
                    put(ATTRIBUTE_LEI, ATTRIBUTE_NAME_SUFFIX_LEI);
                    put(ATTRIBUTE_EORI, ATTRIBUTE_NAME_SUFFIX_EORI);
                    put(ATTRIBUTE_SEED, ATTRIBUTE_NAME_SUFFIX_SEED);
                    put(ATTRIBUTE_SIC, ATTRIBUTE_NAME_SUFFIX_SIC);
                }
            }
    );
    /**
     * maps attribute names to their xsd types
     */
    public final static Map<String, String> ATTRIBUTES_TO_TYPESNAMES = Collections.unmodifiableMap(
            new HashMap<String, String>(){
                {
                    put(ATTRIBUTE_GIVENNAME, ATTRIBUTE_NAME_SUFFIX_GIVENNAME+TYPE_SUFFIX);
                    put(ATTRIBUTE_FIRSTNAME, ATTRIBUTE_NAME_SUFFIX_FIRSTNAME+TYPE_SUFFIX);
                    put(ATTRIBUTE_DATEOFBIRTH, ATTRIBUTE_NAME_SUFFIX_DATEOFBIRTH+TYPE_SUFFIX);
                    put(ATTRIBUTE_PERSONIDENTIFIER, ATTRIBUTE_NAME_SUFFIX_PERSONIDENTIFIER+TYPE_SUFFIX);
                    put(ATTRIBUTE_BIRTHNAME, ATTRIBUTE_NAME_SUFFIX_BIRTHNAME+TYPE_SUFFIX);
                    put(ATTRIBUTE_CURRENTADDRESS, ATTRIBUTE_NAME_SUFFIX_CURRENTADDRESS+TYPE_SUFFIX);
                    put(ATTRIBUTE_PLACEOFBIRTH, ATTRIBUTE_NAME_SUFFIX_PLACEOFBIRTH+TYPE_SUFFIX);
                    put(ATTRIBUTE_GENDER, ATTRIBUTE_NAME_SUFFIX_GENDER+TYPE_SUFFIX);
                    put(ATTRIBUTE_LEGALIDENTIFIER, ATTRIBUTE_NAME_SUFFIX_LEGALIDENTIFIER+TYPE_SUFFIX);
                    put(ATTRIBUTE_LEGALADDRESS, "LegalPersonAddressType");
                    put(ATTRIBUTE_LEGALNAME, ATTRIBUTE_NAME_SUFFIX_LEGALNAME+TYPE_SUFFIX);
                    put(ATTRIBUTE_VATREGISTRATION,"VATRegistrationNumberType" );
                    put(ATTRIBUTE_TAXREFERENCE, ATTRIBUTE_NAME_SUFFIX_TAXREFERENCE+TYPE_SUFFIX);
                    put(ATTRIBUTE_BUSINESSCODE, ATTRIBUTE_NAME_SUFFIX_BUSINESSCODE+TYPE_SUFFIX);
                    put(ATTRIBUTE_LEI, ATTRIBUTE_NAME_SUFFIX_LEI+TYPE_SUFFIX);
                    put(ATTRIBUTE_EORI, ATTRIBUTE_NAME_SUFFIX_EORI+TYPE_SUFFIX);
                    put(ATTRIBUTE_SEED, ATTRIBUTE_NAME_SUFFIX_SEED+TYPE_SUFFIX);
                    put(ATTRIBUTE_SIC, ATTRIBUTE_NAME_SUFFIX_SIC+TYPE_SUFFIX);
                }
            }
    );
}
