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
package eu.stork.peps.auth.util.tests;

/**
 * This enum class contains all the STORK PEPS testing constants.
 * 
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com,
 * @version $Revision: $, $Date: $
 */
public enum TestingConstants {
  /**
   * Represents the 'all' constant.
   */
  ALL_CONS("all"),
  /**
   * Represents the 'Idade' constant.
   */
  ALLOWED_ATTRIBUTES_CONS("Idade;"),
  /**
   * Represents the 'ASSERTION_URL' constant.
   */
  ASSERTION_URL_CONS("ASSERTION_URL"),
  /**
   * Represents the 'DESTINATION_CONS' constant.
   */
  DESTINATION_CONS("SP-URL"),
  /**
   * Represents the '' constant.
   */
  EMPTY_CONS(""),
  /**
   * Represents the 'ERROR_CODE' constant.
   */
  ERROR_CODE_CONS("ERROR_CODE"),
  /**
   * Represents the 'ERROR_MESSAGE' constant.
   */
  ERROR_MESSAGE_CONS("ERROR_MESSAGE"),
  /**
   * Represents the 'LOCAL-SPEPS' constant.
   */
  ISSUER_CONS("LOCAL-SPEPS"),
  /**
   * Represents the 'LOCAL' constant.
   */
  
    LOCAL_CONS("LO"),
   /**
   * Represents the 'LOCAL_DUMMY_URL' constant.
   */
  LOCAL_URL_CONS("LOCAL_DUMMY_URL"),
  /**
   * Represents the 'maxQaa' constant.
   */
  MAX_QAA_CONS("4"),
  /**
   * Represents the 'minQaa' constant.
   */
  MIN_QAA_CONS("1"),
  /**
   * Represents the '1' constant.
   */
  ONE_CONS("1"),
  /**
   * Represents the 'PROVIDERNAME_CERT' constant.
   */
  PROVIDERNAME_CERT_CONS("PROVIDERNAME_CERT"),
  /**
   * Represents the 'SP_PROV' constant.
   */
  PROVIDERNAME_CONS("SP_PROV"),
  /**
   * Represents the 'SP_RELAY' constant.
   */
  SP_RELAY_STATE_CONS("SP_RELAY"),
  /**
   * Represents the 'qaaLevel' constant.
   */
  QAALEVEL_CONS("3"),
  /**
   * Represents the 'samlId' constant.
   */
    SAML_ID_CONS("_12341234123412341234123412341234"),
  /**
   * Represents the 'SAML_ISSUER_CONS' constant.
   */
  SAML_ISSUER_CONS("http://SPEPSmetadata"),
  /**
   * Represents the 'samlInstance' constant.
   */
  SAML_INSTANCE_CONS("CPEPS"),
  /**
   * Represents the 'SAML_TOKEN_CONS' constant.
   */
  SAML_TOKEN_CONS("<saml>...</saml>"),
  /**
   * Represents the 'spid' constant.
   */
  SPID_CONS("SP"),
  /**
   * Represents the 'SP_APP' constant.
   */
  SP_APPLICATION_CONS("SP_APP"),
  /**
   * Represents the 'SP_INST' constant.
   */
  SP_INSTITUTION_CONS("SP_INST"),
  /**
   * Represents the 'SP_SECT' constant.
   */
  SP_SECTOR_CONS("SP_SECT"),
  /**
   * Represents the 'SUB_ERROR_CODE' constant.
   */
  SUB_ERROR_CODE_CONS("SUB_ERROR_CODE"),
  /**
   * Represents the 'USER_IP_CONS' constant.
   */
  USER_IP_CONS("10.10.10.10"),
  /**
   * Represents the 'true' constant.
   */
  TRUE_CONS("true"),
  /**
   * Represents the '2' constant.
   */
  TWO_CONS("2"),
  /**
   * Represents a skew time of 0
   */
  SKEW_ZERO_CONS("0");
  
  /**
   * Represents the constant's value.
   */
  private String value;
  
  /**
   * Solo Constructor.
   * 
   * @param nValue The Constant value.
   */
  private TestingConstants(final String nValue) {
    this.value = nValue;
  }
  
  /**
   * Return the Constant Value.
   * 
   * @return The constant value.
   */
  public String toString() {
    return value;
  }
  
  /**
   * Return the Constant integer Value.
   * 
   * @return The constant int value.
   */
  public int intValue() {
    return Integer.valueOf(value);
  }
  
  /**
   * Return the SP Constant plus ".qaalevel" string.
   * 
   * @return The SP constant value plus '.qaalevel" string.
   */
  public String getQaaLevel() {
    return SPID_CONS.toString() + ".qaalevel";
  }
}
