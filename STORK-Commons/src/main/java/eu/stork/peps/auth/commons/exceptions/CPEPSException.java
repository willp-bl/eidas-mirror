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
package eu.stork.peps.auth.commons.exceptions;

/**
 * This exception is thrown by the C-PEPS service and holds the relative
 * information to present to the citizen.
 *
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com, hugo.magalhaes@multicert.com,
 *         paulo.ribeiro@multicert.com
 * @version $Revision: 1.9 $, $Date: 2010-11-17 05:15:28 $
 */
public class CPEPSException extends AbstractPEPSException {

    /**
     * Serial id.
     */
    private static final long serialVersionUID = -4012295047127999362L;

    public CPEPSException(final String code, final String message) {

        super(code, message);

    }

    /**
     * Exception Constructor with two Strings representing the errorCode and
     * errorMessage as parameters.
     *
     * @param samlToken The SAML Token.
     * @param code      The error code value.
     * @param message   The error message value.
     */
    public CPEPSException(final String samlToken, final String code,
                          final String message) {

        super(message);
        this.setErrorCode(code);
        this.setErrorMessage(message);
        this.setSamlTokenFail(samlToken);
    }

    /**
     * Exception Constructor with two Strings representing the errorCode and
     * errorMessage as parameters.
     *
     * @param samlToken The SAML Token.
     * @param code      The error code value.
     * @param message   The error message value.
     * @param cause     The original exception;
     */
    public CPEPSException(final String samlToken, final String code,
                          final String message, final Throwable cause) {

        super(message, cause);
        this.setErrorCode(code);
        this.setErrorMessage(message);
        this.setSamlTokenFail(samlToken);
    }

    public CPEPSException(final String samlToken, final String code, final String message,
                          final Throwable cause, String userErrorCode, String userErrorMessage) {

        super(code, message, cause, userErrorCode, userErrorMessage);
        this.setSamlTokenFail(samlToken);
    }

    /**
     * Constructor with SAML Token as argument. Error message and error code are
     * embedded in the SAML.
     *
     * @param samlToken The error SAML Token.
     */
    public CPEPSException(final String samlToken) {
        super(samlToken);

    }

    /**
     * {@inheritDoc}
     */
    public final String getMessage() {
        return this.getErrorMessage() + " (" + this.getErrorCode() + ")";
    }

}
