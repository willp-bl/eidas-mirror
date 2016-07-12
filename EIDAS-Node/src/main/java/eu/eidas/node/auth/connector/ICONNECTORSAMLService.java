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
package eu.eidas.node.auth.connector;

import java.util.Map;

import eu.eidas.auth.commons.EIDASAuthnRequest;

/**
 * Interface for working with SAMLObjects.
 *
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com, hugo.magalhaes@multicert.com,
 *         paulo.ribeiro@multicert.com
 * @version $Revision: 1.34 $, $Date: 2010-11-18 23:17:50 $
 */
public interface ICONNECTORSAMLService {

    /**
     * {@link Base64} decodes the incoming SAML Token.
     *
     * @param parameters A map containing the SAML token.
     * @param errorCode  In case of error specifies the code that should be used.
     * @param isRequest  Fetch the SAML from the request or the response?
     * @return The decoded SAML token in the format of byte array.
     * @see Map
     */
    byte[] getSAMLToken(Map<String, String> parameters, String errorCode,
                        boolean isRequest);

    /**
     * {@link Base64} decodes the incoming SAML Token.
     *
     * @param parameters A map containing the SAML artifact.
     * @param errorCode  In case of error specifies the code that should be used.
     * @param isRequest  Fetch the SAML from the request or the response?
     * @return The decoded SAML token in the format of byte array.
     * @see Map
     */
    byte[] getSAMLArtifact(final Map<String, String> parameters,
                                  final String errorCode, final boolean isRequest);

    /**
     * Validates the SAML Token request and checks if the SP is reliable.
     *
     * @param samlToken  The token to validate.
     * @param parameters A map of necessary arguments.
     * @return An authentication request created from the SAML token.
     * @see EIDASAuthnRequest
     * @see Map
     */
    EIDASAuthnRequest processAuthenticationRequest(byte[] samlToken,
                                                   Map<String, String> parameters);

    /**
     * Validates the response SAML Token.
     *
     * @param samlToken   The SAML token to validate.
     * @param authnData   The authentication request object.
     * @param spAuthnData The authentication request object from the SP.
     * @param remoteAddr  The address of the citizen (used in case of error).
     * @return The authentication response with a new
     *         {@link PersonalAttributeList}.
     * @see EIDASAuthnRequest
     */
    EIDASAuthnRequest processAuthenticationResponse(byte[] samlToken,
                                                    EIDASAuthnRequest authnData, EIDASAuthnRequest spAuthnData,
                                                    String remoteAddr);

    /**
     * Creates a SAML Authentication Request to send to SP.
     *
     * @param authData An authentication request.
     * @return A new authentication request with the SAML token embedded.
     * @see EIDASAuthnRequest
     */
    EIDASAuthnRequest generateSpAuthnRequest(EIDASAuthnRequest authData);

    /**
     * Creates a SAML Authentication Request to send to Service.
     *
     * @param authData An authentication request.
     * @return A new authentication request with the SAML token embedded.
     * @see EIDASAuthnRequest
     */
    EIDASAuthnRequest generateServiceAuthnRequest(EIDASAuthnRequest authData);

    /**
     * Generates a response's SAML token.
     *
     * @param authData      An authentication request.
     * @param ipUserAddress Citizen's IP address.
     * @return The response's SAML token in the format of byte array.
     * @see EIDASAuthnRequest
     */
    byte[] generateAuthenticationResponse(EIDASAuthnRequest authData,
                                          String ipUserAddress);

    /**
     * Generates a response's SAML token in case of error.
     *
     * @param inResponseTo  The request that gave origin to this response.
     * @param issuer        The request's Issuer.
     * @param destination   The request's destination.
     * @param ipUserAddress The citizen's IP address.
     * @param statusCode    The status code.
     * @param subCode       The sub status code.
     * @param message       The error message.
     * @return The response's SAML token in the format of byte array.
     */
    byte[] generateErrorAuthenticationResponse(String inResponseTo,
                                               String issuer, String destination, String ipUserAddress, String statusCode,
                                               String subCode, String message);

    /**
     * Checks if all mandatory attributes have the status to Available.
     *
     * @param authData The authentication request.
     * @param ipUserAddr The citizen's IP address.
     *
     * @see EIDASAuthnRequest
     */
    void checkMandatoryAttributes(EIDASAuthnRequest authData, String ipUserAddr);

    String getMetadata();

    /**
     * removes the requested attributes present in authData and not supported by the service
     * (through the use of metadata)
     * @param authData
     * @param parameters
     */
    void filterServiceSupportedAttrs(EIDASAuthnRequest authData,Map<String, String> parameters);
}
