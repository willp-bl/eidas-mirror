package eu.eidas.auth.engine.core.eidas.spec;

import org.joda.time.DateTime;

import eu.eidas.auth.commons.attribute.AttributeDefinition;
import eu.eidas.auth.commons.attribute.AttributeRegistries;
import eu.eidas.auth.commons.attribute.AttributeRegistry;
import eu.eidas.auth.commons.protocol.eidas.impl.Gender;
import eu.eidas.auth.commons.protocol.eidas.impl.PostalAddress;

/**
 * Both NaturalPerson and LegalPerson from the eIDAS Specification.
 * <p>
 * This class contains all the attribute definitions specified in eIDAS.
 *
 * @since 2016-05-0
 */
public final class EidasSpec {

    public static final class Definitions {

        public static final AttributeDefinition<String> PERSON_IDENTIFIER = NaturalPersonSpec.Definitions.PERSON_IDENTIFIER;

        public static final AttributeDefinition<String> CURRENT_FAMILY_NAME = NaturalPersonSpec.Definitions.CURRENT_FAMILY_NAME;

        public static final AttributeDefinition<String> CURRENT_GIVEN_NAME = NaturalPersonSpec.Definitions.CURRENT_GIVEN_NAME;

        public static final AttributeDefinition<DateTime> DATE_OF_BIRTH = NaturalPersonSpec.Definitions.DATE_OF_BIRTH;

        public static final AttributeDefinition<String> BIRTH_NAME = NaturalPersonSpec.Definitions.BIRTH_NAME;

        public static final AttributeDefinition<String> PLACE_OF_BIRTH = NaturalPersonSpec.Definitions.PLACE_OF_BIRTH;

        public static final AttributeDefinition<PostalAddress> CURRENT_ADDRESS = NaturalPersonSpec.Definitions.CURRENT_ADDRESS;

        public static final AttributeDefinition<Gender> GENDER = NaturalPersonSpec.Definitions.GENDER;

        public static final AttributeDefinition<String> LEGAL_PERSON_IDENTIFIER =
                LegalPersonSpec.Definitions.LEGAL_PERSON_IDENTIFIER;

        public static final AttributeDefinition<String> LEGAL_NAME = LegalPersonSpec.Definitions.LEGAL_NAME;

        public static final AttributeDefinition<PostalAddress> LEGAL_ADDRESS = LegalPersonSpec.Definitions.LEGAL_ADDRESS;

        public static final AttributeDefinition<String> VAT_REGISTRATION = LegalPersonSpec.Definitions.VAT_REGISTRATION;

        public static final AttributeDefinition<String> TAX_REFERENCE = LegalPersonSpec.Definitions.TAX_REFERENCE;

        public static final AttributeDefinition<String> D_2012_17_EU_IDENTIFIER =
                LegalPersonSpec.Definitions.D_2012_17_EU_IDENTIFIER;

        public static final AttributeDefinition<String> LEI = LegalPersonSpec.Definitions.LEI;

        public static final AttributeDefinition<String> EORI = LegalPersonSpec.Definitions.EORI;

        public static final AttributeDefinition<String> SEED = LegalPersonSpec.Definitions.SEED;

        public static final AttributeDefinition<String> SIC = LegalPersonSpec.Definitions.SIC;

        private Definitions() {
        }
    }

    public static final AttributeRegistry REGISTRY =
            AttributeRegistries.copyOf(NaturalPersonSpec.REGISTRY, LegalPersonSpec.REGISTRY);

    private EidasSpec() {
    }
}
