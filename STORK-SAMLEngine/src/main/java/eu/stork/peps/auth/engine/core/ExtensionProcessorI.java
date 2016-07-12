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
package eu.stork.peps.auth.engine.core;

import eu.stork.peps.auth.commons.STORKAuthnRequest;
import eu.stork.peps.auth.engine.STORKSAMLEngine;
import eu.stork.peps.exceptions.STORKSAMLEngineException;
import org.opensaml.saml2.common.Extensions;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AuthnRequest;

import java.util.List;
import java.util.Set;

/**
 * parse or generate a SAML format (either STORK or eIDAS)
 */
public interface ExtensionProcessorI {
    /**
     * @param extensions
     * @return a parsed request extrancted from the SAML extensions
     * @throws STORKSAMLEngineException
     */
    STORKAuthnRequest processExtensions(final Extensions extensions) throws STORKSAMLEngineException;

    /**
     * @return the id of the configured request validator
     */
    String getRequestValidatorId();

    /**
     * @return the id of the configured response validator
     */
    String getResponseValidatorId();

    /**
     * @param engine
     * @param request the request for which the extension will be generated
     * @return a SAML extension based on the request
     * @throws STORKSAMLEngineException
     */
    Extensions generateExtensions(final STORKSAMLEngine engine, final STORKAuthnRequest request) throws STORKSAMLEngineException;

    /**
     * @return the prefix used for identifying the attributes this processor knows to deal with
     */
    String namePrefix();

    SAMLExtensionFormat getFormat();

    /**
     * configuration for the generator and processor
     */
    void configureExtension();

    /**
     * @return a set containing the names of supported attributes names
     */
    Set<String> getSupportedAttributes();

    /**
     * verify if the request is compatible with the processor
     * @param request
     * @return
     */
    boolean isValidRequest(AuthnRequest request);

    /**
     * Generate attribute from a list of values.
     *
     * @param name the name of the attribute.
     * @param values the value of the attribute.
     * @param isHashing the is hashing with "SHA-512" algorithm.
     * @param status the status of the parameter: "Available", "NotAvailable" or
     *            "Withheld".
     *
     * @return the attribute
     *
     * @throws STORKSAMLEngineException the STORKSAML engine exception
     */
    Attribute generateAttrSimple(final String name,
                                        final String status, final List<String> values,
                                        final boolean isHashing) throws STORKSAMLEngineException;

}