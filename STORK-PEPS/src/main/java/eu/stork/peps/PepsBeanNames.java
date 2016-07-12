/*
 * Copyright (c) 2015 by European Commission
 *
 * Licensed under the EUPL, Version 1.1 or - as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence");
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 * http://www.osor.eu/eupl/european-union-public-licence-eupl-v.1.1
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 *
 * This product combines work with different licenses. See the "NOTICE" text
 * file for details on the various modules and licenses.
 * The "NOTICE" text file is part of the distribution. Any derivative works
 * that you distribute must include a readable copy of the "NOTICE" text file.
 *
 */

package eu.stork.peps;

/**
 * See "Effective Java edition 2 (Joshua Bloch - Addison Wesley 20012)" item 30
 */
public enum PepsBeanNames {
    S_PEPS_CONTROLLER("sPepsController"),
    C_PEPS_CONTROLLER("cPepsController"),
    CALLBACK_URL("callbackURL"),
    STR_ATTR_LIST("strAttrList"),
    USERNAME("username"),
    CPEPS_URL("cpepsUrl"),
    SP_URL("spUrl"),
    SAML_REQUEST("SAMLRequest"),
    SAML_RESPONSE("SAMLResponse"),
    RELAY_STATE("RelayState"),
    EXCEPTION("exception"),
    SP_ID("spId"),
    CITIZEN_CONSENT_URL("citizenConsentUrl"),
    ATTR_LIST("attrList"),
    PLACEHOLDER_CONFIG("placeholderConfig"),
    SYSADMIN_MESSAGE_RESOURCES("sysadminMessageSource"),
    REDIRECT_URL("redirectUrl"),
    SAML_TOKEN("samlToken"),
    SAML_TOKEN_FAIL("samlTokenFail"),
    QAA_LEVEL("qaaLevel"),
    PAL("pal"),
    AP_RESPONSE("springManagedAPResponse"),
    SECURITY_CONFIG("springManagedSecurityConfig"),
    CPEPS_BINDING("cpepsBinding"),
    SERVICE_METADATA_GENERATOR("serviceMetadataGeneratorIDP"),
    SERVICE_AS_REQUESTER_METADATA_GENERATOR("serviceMetadataGeneratorSP"),
    CONNECTOR_METADATA_GENERATOR("connectorMetadataGeneratorSP"),
    CONNECTOR_AS_IDP_METADATA_GENERATOR("connectorMetadataGeneratorIDP"),
    EIDAS_ATTRIBUTES_PARAM("eidasAttributes"),
    LOA_VALUE("LoA"),
    ;
    /**
     * constant name.
     */
    private String name;

    /**
     * Constructor
     * @param name name of the bean
     */
    PepsBeanNames(final String name){
        this.name = name;
    }

    @Override
    public String toString() {
        return name;

    }
}
