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
package eu.stork.peps.auth.commons;

import java.util.HashMap;
import java.util.Map;

/**
 * This enum class contains all the STORK PEPS, Commons and Specific errors
 * constant identifiers.
 *
 */
public enum PEPSErrors {

  /**
   * Represents the 'authenticationFailed' constant error identifier.
   */
  AUTHENTICATION_FAILED_ERROR("authenticationFailed"),
  /**
   * Represents the 'spCountrySelector.errorCreatingSAML' constant error
   * identifier.
   */
  SP_COUNTRY_SELECTOR_ERROR_CREATE_SAML("spCountrySelector.errorCreatingSAML"),
  /**
   * Represents the 'spCountrySelector.destNull' constant error identifier.
   */
  SP_COUNTRY_SELECTOR_DESTNULL("spCountrySelector.destNull"),
  /**
   * Represents the 'spCountrySelector.invalidAttr' constant error identifier.
   */
  SP_COUNTRY_SELECTOR_INVALID_ATTR("spCountrySelector.invalidAttr"),
  /**
   * Represents the 'spCountrySelector.invalidProviderName' constant error
   * identifier.
   */
  SP_COUNTRY_SELECTOR_INVALID_PROVIDER_NAME(
    "spCountrySelector.invalidProviderName"),
  /**
   * Represents the 'spCountrySelector.invalidQaaSPid' constant error
   * identifier.
   */
  SP_COUNTRY_SELECTOR_INVALID_QAASPID("spCountrySelector.invalidQaaSPid"),
  /**
   * Represents the 'spCountrySelector.invalidSpId' constant error identifier.
   */
  SP_COUNTRY_SELECTOR_INVALID_SPID("spCountrySelector.invalidSpId"),
  /**
   * Represents the 'spCountrySelector.invalidSPQAA' constant error identifier.
   */
  SP_COUNTRY_SELECTOR_INVALID_SPQAA("spCountrySelector.invalidSPQAA"),
  /**
   * Represents the 'spCountrySelector.invalidSpURL' constant error identifier.
   */
  SP_COUNTRY_SELECTOR_INVALID_SPURL("spCountrySelector.invalidSpURL"),

    /**
     * Represents the 'spCountrySelector.invalidCountry' constant error identifier.
     */
    SP_COUNTRY_SELECTOR_INVALID("spCountrySelector.invalidCountry"),


    /**
   * Represents the 'spCountrySelector.spNotAllowed' constant error identifier.
   */
  SP_COUNTRY_SELECTOR_SPNOTALLOWED("spCountrySelector.spNotAllowed"),

  /**
   * Represents the 'sProviderAction.errorCreatingSAML' constant error
   * identifier.
   */
  SPROVIDER_SELECTOR_ERROR_CREATE_SAML("sProviderAction.errorCreatingSAML"),
  /**
   * Represents the 'sProviderAction.attr' constant error identifier.
   */
  SPROVIDER_SELECTOR_INVALID_ATTR("sProviderAction.invalidAttr"),
  /**
   * Represents the 'sProviderAction.country' constant error identifier.
   */
  SPROVIDER_SELECTOR_INVALID_COUNTRY("sProviderAction.invalidCountry"),
  /**
   * Represents the 'sProviderAction.relayState' constant error identifier.
   */
  SPROVIDER_SELECTOR_INVALID_RELAY_STATE("sProviderAction.invalidRelayState"),
  /**
   * Represents the 'sProviderAction.saml' constant error identifier.
   */
  SPROVIDER_SELECTOR_INVALID_SAML("sProviderAction.invalidSaml"),
  /**
   * Represents the 'sProviderAction.spAlias' constant error identifier.
   */
  SPROVIDER_SELECTOR_INVALID_SPALIAS("sProviderAction.invalidSPAlias"),
  /**
   * Represents the 'sProviderAction.spDomain' constant error identifier.
   */
  SPROVIDER_SELECTOR_INVALID_SPDOMAIN("sProviderAction.invalidSPDomain"),
  /**
   * Represents the 'sProviderAction.spId' constant error identifier.
   */
  SPROVIDER_SELECTOR_INVALID_SPID("sProviderAction.invalidSPId"),
  /**
   * Represents the 'sProviderAction.spQAA' constant error identifier.
   */
  SPROVIDER_SELECTOR_INVALID_SPQAA("sProviderAction.invalidSPQAA"),
  /**
   * Represents the 'sProviderAction.spQAAId' constant error identifier.
   */
  SPROVIDER_SELECTOR_INVALID_SPQAAID("sProviderAction.invalidSPQAAId"),
  /**
   * Represents the 'sProviderAction.spRedirect' constant error identifier.
   */
  SPROVIDER_SELECTOR_INVALID_SPREDIRECT("sProviderAction.invalidSPRedirect"),
  /**
   * Represents the 'sProviderAction.invalidSPProviderName' constant error
   * identifier.
   */
  SPROVIDER_SELECTOR_INVALID_SP_PROVIDERNAME(
    "sProviderAction.invalidSPProviderName"),
  /**
   * Represents the 'sProviderAction.spNotAllowed' constant error identifier.
   */
  SPROVIDER_SELECTOR_SPNOTALLOWED("sProviderAction.spNotAllowed"),


  /**
   * Represents the 'internalError' constant error identifier.
   */
  INTERNAL_ERROR("internalError"),

  /**
   * Represents the 'colleagueRequest.attrNull' constant error identifier.
   */
  COLLEAGUE_REQ_ATTR_NULL("colleagueRequest.attrNull"),
  /**
   * Represents the 'colleagueRequest.errorCreatingSAML' constant error
   * identifier.
   */
  COLLEAGUE_REQ_ERROR_CREATE_SAML("colleagueRequest.errorCreatingSAML"),
  /**
   * Represents the 'colleagueRequest.invalidCountryCode' constant error
   * identifier.
   */
  COLLEAGUE_REQ_INVALID_COUNTRYCODE("colleagueRequest.invalidCountryCode"),
  /**
   * Represents the 'colleagueRequest.invalidDestUrl' constant error identifier.
   */
  COLLEAGUE_REQ_INVALID_DEST_URL("colleagueRequest.invalidDestUrl"),
  /**
   * Represents the 'colleagueRequest.invalidQaa' constant error identifier.
   */
  COLLEAGUE_REQ_INVALID_QAA("colleagueRequest.invalidQaa"),
  /**
   * Represents the 'colleagueRequest.invalidRedirect' constant error
   * identifier.
   */
  COLLEAGUE_REQ_INVALID_REDIRECT("colleagueRequest.invalidRedirect"),
  /**
   * Represents the 'colleagueRequest.invalidSAML' constant error identifier.
   */
  COLLEAGUE_REQ_INVALID_SAML("colleagueRequest.invalidSAML"),


  /**
   * Represents the 'cpepsRedirectUrl' constant error identifier.
   */
  CPEPS_REDIRECT_URL("cpepsRedirectUrl"),
  /**
   * Represents the 'spepsRedirectUrl' constant error identifier.
   */
  SPEPS_REDIRECT_URL("spepsRedirectUrl"),
  /**
   * Represents the 'sProviderAction.invCountry' constant error identifier.
   */
  SP_ACTION_INV_COUNTRY("sProviderAction.invCountry"),

  /**
   * Represents the 'providernameAlias.invalid' constant error identifier.
   */
  PROVIDER_ALIAS_INVALID("providernameAlias.invalid"),


  /**
   * Represents the 'cPeps.attrNull' constant error identifier.
   */
  CPEPS_ATTR_NULL("cPeps.attrNull"),

  /**
   * Represents the 'colleagueResponse.invalidSAML' constant error identifier.
   */
  COLLEAGUE_RESP_INVALID_SAML("colleagueResponse.invalidSAML"),

  /**
   * Represents the 'citizenNoConsent.mandatory' constant error identifier.
   */
  CITIZEN_NO_CONSENT_MANDATORY("citizenNoConsent.mandatory"),
  /**
   * Represents the 'citizenResponse.mandatory' constant error identifier.
   */
  CITIZEN_RESPONSE_MANDATORY("citizenResponse.mandatory"),
  /**
   * Represents the 'attVerification.mandatory' constant error identifier.
   */
  ATT_VERIFICATION_MANDATORY("attVerification.mandatory"),
  /**
   * Represents the 'attrValue.verification' constant error identifier.
   */
  ATTR_VALUE_VERIFICATION("attrValue.verification"),

  /**
   * Represents the 'audienceRestrictionError' constant error identifier.
   */
  AUDIENCE_RESTRICTION("audienceRestrictionError"),
  /**
   * Represents the 'auRequestIdError' constant error identifier.
   */
  AU_REQUEST_ID("auRequestIdError"),
  /**
   * Represents the 'domain' constant error identifier.
   */
  DOMAIN("domain"),
  /**
   * Represents the 'hash.error' constant error identifier.
   */
  HASH_ERROR("hash.error"),
  /**
   * Represents the 'invalidAttributeList' constant error identifier.
   */
  INVALID_ATTRIBUTE_LIST("invalidAttributeList"),
  /**
   * Represents the 'invalidAttributeValue' constant error identifier.
   */
  INVALID_ATTRIBUTE_VALUE("invalidAttributeValue"),
  /**
   * Represents the 'qaaLevel' constant error identifier.
   */
  QAALEVEL("qaaLevel"),
  /**
   * Represents the 'requests' constant error identifier.
   */
  REQUESTS("requests"),
  /**
   * Represents the 'SPSAMLRequest' constant error identifier.
   */
  SP_SAML_REQUEST("SPSAMLRequest"),
  /**
   * Represents the 'spepsSAMLRequest' constant error identifier.
   */
  SPEPS_SAML_REQUEST("spepsSAMLRequest"),
  /**
   * Represents the 'IdPSAMLResponse' constant error identifier.
   */
  IDP_SAML_RESPONSE("IdPSAMLResponse"),
  /**
   * Represents the 'cpepsSAMLResponse' constant error identifier.
   */
  CPEPS_SAML_RESPONSE("cpepsSAMLResponse"),
  /**
   * Represents the 'cpepsSAMLResponse' constant error identifier.
   */
  SPEPS_SAML_RESPONSE("spepsSAMLResponse"),
  /**
   * Represents the 'session' constant error identifier.
   */
  SESSION("session"),
  /**
   * Represents the 'invalid.session' constant error identifier.
   */
  INVALID_SESSION("invalid.session"),
  /**
   * Represents the 'invalid.sessionId' constant error identifier.
   */
  INVALID_SESSION_ID("invalid.sessionId"),
  /**
   * Represents the 'sessionError' constant error identifier.
   */
  MISSING_SESSION_ID("sessionError"),

/*    *//**
     * Plugin is loaded but inactive
     *//*
    PEPS_PLUGIN_INACTIVE("inactive.plugin"),*/

    /**
     * Plugin config has errors
     */
    SPWARE_CONFIG_ERROR("spWare.config.error"),

     /**
     * Error for propagating the SAML XEE attack error
     */
    DOC_TYPE_NOT_ALLOWED("docTypeNotPermited"),
    DOC_TYPE_NOT_ALLOWED_CODE("203013"),
    //an invalid certificate used for generating the signature
    INVALID_CERTIFICATE_SIGN("invalidCertificateSign.error"),
    //an invalid certificate was used for the signature of the received signed object
    INVALID_SIGNATURE_ALGORITHM("invalidReceivedSignAlgo.error"),
    INVALID_PROTOCOL_BINDING("invalidProtocolBinding.error"),
    INVALID_ASSERTION_SIGNATURE("invalidSamlAssertionSignature.error"),
    INVALID_ENCRYPTION_ALGORITHM("invalidEncryptionAlgorithm.error", false),
    SAML_ENGINE_CONFIGURATION_ERROR("samlEngine.configuration.error"),
    MESSAGE_VALIDATION_ERROR("message.validation.error"),
    SAML_ENGINE_INVALID_KEYSTORE("samlengine.invalid.keystore", false),
    SAML_ENGINE_INVALID_CERTIFICATE("samlengine.invalid.certificate", false),
    SAML_ENGINE_UNTRUSTED_CERTIFICATE("samlengine.untrusted.certificate", false),
    SAML_ENGINE_LOAD_PROVIDER("samlengine.load.provider", false),
    SAML_ENGINE_INVALID_METADATA("samlengine.invalid.metadata.error", false),
    CONSOLE_METADATA_ISSUER_ALREADY_EXISTS("err.metadata.already.exists"),
    CONSOLE_METADATA_FILE_ALREADY_EXISTS("err.metadata.file.already.exists"),
    CONSOLE_METADATA_FILE_PARSING("err.metadata.file.invalid.format"),
    SAML_ENGINE_UNENCRYPTED_RESPONSE("samlengine.unencrypted.response"),
    EIDAS_MANDATORY_ATTRIBUTES("missing.mandatory.attribute"),
    SAML_ENGINE_INVALID_METADATA_SOURCE("samlengine.invalid.metadata.source.error", false),
    SAML_ENGINE_NO_METADATA("samlengine.metadata.retrieval.error", false),
    /**
     * Represents the 'colleagueRequest.invalidLoA' constant error identifier.
     */
    COLLEAGUE_REQ_INVALID_LOA("colleagueRequest.invalidLoA"),
    COLLEAGUE_REQ_INCONSISTENT_SPTYPE("inconsistent.sptype"),
    COLLEAGUE_REQ_MISSING_SPTYPE("missing.sptype"),
    SERVICE_PROVIDER_INVALID_LOA("serviceProviderRequest.invalidLoA"),
    SPEPS_INVALID_SPTYPE("speps.invalid.sptype"),
    /**
     * LoA is not not one of http://eidas.europa.eu/LoA/low, http://eidas.europa.eu/LoA/substantial, http://eidas.europa.eu/LoA/high
     */
    INVALID_LOA_VALUE("invalidLoA"),
    MESSAGF_FORMAT_UNSUPPORTED("samlengine.message.format.unsupported"),
    ;
    private static Map<String, PEPSErrors> errorsByCode =new HashMap<String, PEPSErrors>();
    private static Map<String, PEPSErrors> errorsByID =new HashMap<String, PEPSErrors>();
    static{
        for(PEPSErrors e:PEPSErrors.values()){
            errorsByCode.put(e.errorCode(), e);
            errorsByID.put(e.error, e);
        }
    }
    public static final String CODE_CONSTANT = ".code";
  public static final String MESSAGE_CONSTANT = ".message";
  public static final String DOT_SEPARATOR   = ".";

    /**
   * Represents the constant's value.
   */
  private String error;
  private boolean showToUser=true;

  /**
   * Solo Constructor.
   *
   * @param nError The Constant error value.
   */
  PEPSErrors(final String nError) {
    this.error = nError;
  }
  PEPSErrors(final String nError, final boolean showToUserArg) {
    this.error = nError;
    this.showToUser= showToUserArg;
  }

  /**
   * Construct the errorCode Constant value.
   *
   * @return The errorCode Constant.
   */
  public String errorCode() {
    return error + CODE_CONSTANT;
  }

  /**
   * Construct the errorCode Constant value with the given code text.
   *
   * @param text the code text to append to the constant.
   *
   * @return The errorCode Constant for the given code text.
   */
  public String errorCode(final String text) {
    return error + DOT_SEPARATOR + text + CODE_CONSTANT;
  }

  /**
   * Construct the errorMessage constant value.
   *
   * @return The errorMessage constant.
   */
  public String errorMessage() {
    return error + MESSAGE_CONSTANT;
  }

  /**
   * Construct the errorMessage Constant value with the given message text.
   *
   * @param text the message text to append to the constant.
   *
   * @return The errorMessage Constant for the given text.
   */
  public String errorMessage(final String text) {
    return error + DOT_SEPARATOR + text + MESSAGE_CONSTANT;
  }

  /**
   * Return the Constant Value.
   *
   * @return The constant value.
   */
  public String toString() {
    return error;
  }

    public static PEPSErrors fromCode(String code){
        if(code!=null && code.endsWith(CODE_CONSTANT)){
            return errorsByCode.get(code);
        }
        return null;
    }
    public static boolean isErrorCode(String code) {
        return null != PEPSErrors.fromCode(code);
    }
    public static PEPSErrors fromID(String id){
        if(id!=null){
            return errorsByID.get(id);
        }
        return null;
    }

  public boolean isShowToUser() {
    return showToUser;
  }
}
