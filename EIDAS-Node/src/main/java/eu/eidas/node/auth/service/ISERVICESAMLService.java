/* 
#   Copyright (c) 2017 European Commission  
#   Licensed under the EUPL, Version 1.2 or – as soon they will be 
#   approved by the European Commission - subsequent versions of the 
#    EUPL (the "Licence"); 
#    You may not use this work except in compliance with the Licence. 
#    You may obtain a copy of the Licence at: 
#    * https://joinup.ec.europa.eu/page/eupl-text-11-12  
#    *
#    Unless required by applicable law or agreed to in writing, software 
#    distributed under the Licence is distributed on an "AS IS" basis, 
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
#    See the Licence for the specific language governing permissions and limitations under the Licence.
 */
/*
 * This work is Open Source and licensed by the European Commission under the
 * conditions of the European Public License v1.1
 *
 * (http://www.osor.eu/eupl/european-union-public-licence-eupl-v.1.1);
 *
 * any use of this file implies acceptance of the conditions of this license.
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,  WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package eu.eidas.node.auth.service;

import eu.eidas.auth.commons.attribute.ImmutableAttributeMap;
import eu.eidas.auth.commons.protocol.IAuthenticationRequest;
import eu.eidas.auth.commons.protocol.IResponseMessage;
import eu.eidas.auth.commons.protocol.eidas.impl.EidasAuthenticationRequest;
import eu.eidas.auth.commons.protocol.impl.AuthenticationResponse;
import eu.eidas.auth.engine.ProtocolEngineI;

import java.util.Collection;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Interface for communicating with the SAMLEngine.
 *
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com, luis.felix@multicert.com,
 *         hugo.magalhaes@multicert.com, paulo.ribeiro@multicert.com
 * @version $Revision: 1.29 $, $Date: 2010-11-18 23:17:50 $
 */
public interface ISERVICESAMLService {

    /**
     * Process the token received the connector.
     * @param bindingFromHttp post or redirect
     * @param samlObj the byte[]
     * @param ipUserAddress  The citizen's IP address.
     * @param relayState the relay state
     * @return the transformed token in an authenticationRequest
     */
    @Nonnull
    IAuthenticationRequest processConnectorRequest(String bindingFromHttp,
                                                   byte[] samlObj,
                                                   String ipUserAddress,
                                                   String relayState);

    /**
     * Process the response received from the IDP.
     *
     * @param originalRequest The original authentication request.
     * @param ipUserAddress The citizen's IP address.
     * @return A byte array containing the SAML Response Token.
     * @see EidasAuthenticationRequest
     */
    IResponseMessage processIdpSpecificResponse(IAuthenticationRequest originalRequest,
                                                AuthenticationResponse response,
                                                String ipUserAddress);

    /**
     * Constructs a SAML response token in case of error.
     *
     * @param authData The authentication request.
     * @param statusCode The status code.
     * @param errorCode The error code.
     * @param subCode The sub status code.
     * @param errorMessage The error message.
     * @param ipUserAddress The citizen's IP address.
     * @param isAuditable Is a auditable saml error?
     * @return A byte array containing the SAML Response.
     * @see EidasAuthenticationRequest
     */
    byte[] generateErrorAuthenticationResponse(IAuthenticationRequest authData,
                                               String statusCode,
                                               String errorCode,
                                               String subCode,
                                               String errorMessage,
                                               String ipUserAddress,
                                               boolean isAuditable);

    /**
     * Checks whether the attribute list contains at least one of the mandatory eIDAS attribute set (either for a
     * natural [person or for a legal person)
     *
     * @param attributes
     */
    boolean checkMandatoryAttributeSet(@Nullable ImmutableAttributeMap attributes);

    /**
     * Checks whether the attribute map satifisfies the rule of representation
     *
     * @param attributes
     */
    boolean checkRepresentativeAttributes(@Nullable ImmutableAttributeMap attributes);

    /**
     * Checks if all the requested mandatory attributes have values.
     *
     * @param requestedAttributes
     * @param responseAttributes
     *
     * @return true if all mandatory attributes have values, false if at least one
     * attribute doesn't have value.
     *
     */
    boolean checkMandatoryAttributes(@Nonnull ImmutableAttributeMap requestedAttributes, @Nonnull ImmutableAttributeMap responseAttributes);

    String getSamlEngineInstanceName();

    ProtocolEngineI getSamlEngine();

    @Nonnull
    IAuthenticationRequest updateRequest(@Nonnull IAuthenticationRequest authnRequest,
                                         @Nonnull ImmutableAttributeMap updatedAttributes);

    @Nonnull
    String getCountryCode();

    @Nonnull
    Collection<String> whitelist(String name);

}
