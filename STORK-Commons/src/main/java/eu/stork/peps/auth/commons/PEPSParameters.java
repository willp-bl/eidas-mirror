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

import java.util.HashSet;
import java.util.Set;

/**
 * This enum class contains all the STORK PEPS, Commons and Specific Parameters.
 * 
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com, hugo.magalhaes@multicert.com,
 *         paulo.ribeiro@multicert.com
 * @version $Revision: 1.13 $, $Date: 2011-07-07 20:48:45 $
 */
public enum PEPSParameters {

  /**
   * Represents the 'apId' parameter constant.
   */
  AP_ID("apId"),
  /**
   * Represents the 'apUrl' parameter constant.
   */
  AP_URL("apUrl"),
  /**
   * Represents the 'ap.number' parameter constant.
   */
  AP_NUMBER("ap.number"),
  
  /**
   * Represents the 'assertionConsumerServiceURL' parameter constant.
   */
  ASSERTION_CONSUMER_S_URL("assertionConsumerServiceURL"),
  
  /**
   * Represents the 'attr' parameter constant.
   */
  ATTRIBUTE("attr"),
  /**
   * Represents the 'attrName' parameter constant.
   */
  ATTRIBUTE_NAME("attrName"),
  /**
   * Represents the 'attrStatus' parameter constant.
   */
  ATTRIBUTE_STATUS("attrStatus"),
  /**
   * Represents the 'attrType' parameter constant.
   */
  ATTRIBUTE_TYPE("attrType"),
  /**
   * Represents the 'attrValue' parameter constant.
   */
  ATTRIBUTE_VALUE("attrValue"),
  /**
   * Represents the 'attrList' parameter constant.
   */
  ATTRIBUTE_LIST("attrList"),
  /**
   * Represents the 'attrTuple' parameter constant.
   */
  ATTRIBUTE_TUPLE("attrTuple"),
  /**
   * Represents the 'attribute-missing' parameter constant.
   */
  ATTRIBUTE_MISSING("attribute-missing"),
  /**
   * Represents the 'attributesNotAllowed' parameter constant.
   */
  ATTRIBUTES_NOT_ALLOWED("attributesNotAllowed"),
  /**
   * Represents the 'authnRequest' parameter constant.
   */
  AUTH_REQUEST("authnRequest"),
  
  /**
   * Represents the 'attrValue.number' parameter constant.
   */
  ATTR_VALUE_NUMBER("attrValue.number"),
  
  /**
   * Represents the 'derivation.date.format' parameter constant.
   */
  DERIVATION_DATE_FORMAT("derivation.date.format"),
  /**
   * Represents the 'deriveAttr.number' parameter constant.
   */
  DERIVE_ATTRIBUTE_NUMBER("deriveAttr.number"),
  
  /**
   * Represents the 'canonicalResidenceAddress' parameter constant.
   */
  COMPLEX_ADDRESS_VALUE("canonicalResidenceAddress"),
  /**
   * Represents the 'consent-type' parameter constant.
   */
  CONSENT_TYPE("consent-type"),
  /**
   * Represents the 'consent-value' parameter constant.
   */
  CONSENT_VALUE("consent-value"),
  /**
   * Represents the 'country' parameter constant.
   */
  COUNTRY("country"),
  /**
   * Represents the 'countryOrigin' parameter constant.
   */
  COUNTRY_ORIGIN("countryOrigin"),
  
  /**
   * Represents the 'cpepsURL' parameter constant.
   */
  CPEPS_URL("cpepsURL"),
  /**
   * Represents the 'callback' parameter constant.
   */
  CPEPS_CALLBACK("callback"),
  /**
   * Represents the 'peps.specificidpredirect.url' parameter constant.
   */
  CPEPS_IDP_CALLBACK_VALUE("peps.specificidpredirect.url"),
  /**
   * Represents the 'peps.specificapredirect.url' parameter constant.
   */
  CPEPS_AP_CALLBACK_VALUE("peps.specificapredirect.url"),
  
  /**
   * Represents the 'errorCode' parameter constant.
   */
  ERROR_CODE("errorCode"),
  /**
   * Represents the 'subCode' parameter constant.
   */
  ERROR_SUBCODE("subCode"),
  /**
   * Represents the 'errorMessage' parameter constant.
   */
  ERROR_MESSAGE("errorMessage"),
  /**
   * Represents the 'errorRedirectUrl' parameter constant.
   */
  ERROR_REDIRECT_URL("errorRedirectUrl"),
  
  /**
   * errorRedirectUrl Represents the 'external-authentication' parameter
   * constant.
   */
  EXTERNAL_AUTH("external-authentication"),
  /**
   * Represents the 'external-ap' parameter constant.
   */
  EXTERNAL_AP("external-ap"),
  /**
   * Represents the 'external-sig-module' parameter constant.
   */
  EXT_SIG_CREATOR_MOD("external-sig-module"),
  
  /**
   * Represents the 'http-x-forwarded-for' parameter constant.
   */
  HTTP_X_FORWARDED_FOR("http-x-forwarded-for"),
  
  /**
   * Represents the 'idp.url' parameter constant.
   */
  IDP_URL("idp.url"),
  /**
   * Represents the 'internal-authentication' parameter constant.
   */
  INTERNAL_AUTH("internal-authentication"),
  /**
   * Represents the 'internal-ap' parameter constant.
   */
  INTERNAL_AP("internal-ap"),
  
  /**
   * Represents the 'samlIssuer' parameter constant.
   */
  ISSUER("samlIssuer"),
  /**
   * Represents the 'samlIssuer.idp' parameter constant.
   */
  ISSUER_IDP("samlIssuer.idp"),
  
  /**
   * Represents the 'mandatory' parameter constant.
   */
  MANDATORY("mandatory"),
  /**
   * Represents the 'mandatoryAttributeMissing' parameter constant.
   */
  MANDATORY_ATTR_MISSING("mandatoryAttributeMissing"),
  /**
   * Represents the 'mandatoryConsentAttrMissing' parameter constant.
   */
  MANDATORY_CONSENT_MISSING("mandatoryConsentAttrMissing"),
  /**
   * Represents the 'optional' parameter constant.
   */
  OPTIONAL("optional"),
  
  /**
   * Represents the 'no-consent-type' parameter constant.
   */
  NO_CONSENT_TYPE("no-consent-type"),
  /**
   * Represents the 'no-consent-value' parameter constant.
   */
  NO_CONSENT_VALUE("no-consent-value"),
  
  /**
   * Represents the 'provider.name' parameter constant.
   */
  PROVIDER_NAME_VALUE("providerName"),
  /**
   * Represents the 'cpeps.askconsent' parameter constant.
   */
  PEPS_ASK_CONSENT("cpeps.askconsent"),
  /**
   * Represents the 'cpeps.askconsentvalue' parameter constant.
   */
  PEPS_ASK_CONSENT_VALUE("cpeps.askconsentvalue"),
  /**
   * Represents the 'pepsAuth' parameter constant.
   */
  PEPS_AUTH_CONSENT("pepsAuth"),
  /**
   * Represents the 'validation.bypass' parameter constant.
   */
  PEPS_BYPASS("validation.bypass"),
  /**
   * Represents the 'cpeps.number' parameter constant.
   */
  PEPS_NUMBER("cpeps.number"),
  /**
   * Represents the 'cpeps.specificapredirect.url' parameter constant.
   */
  PEPS_SPECIFIC_URL("cpeps.specificapredirect.url"),
  
  /**
   * Represents the 'qaaLevel' parameter constant.
   */
  QAALEVEL("qaaLevel"),
  
  /**
   * Represents the 'speps.redirectUrl' parameter constant.
   */
  SPEPS_REDIRECT_URL("speps.redirectUrl"),
  
  /**
   * Represents the 'sp.redirectUrl' parameter constant.
   */
  SP_REDIRECT_URL("sp.redirectUrl"),
  /**
   * Represents the 'cpeps.redirectUrl' parameter constant.
   */
  CPEPS_REDIRECT_URL("cpeps.redirectUrl"),
  /**
   * Represents the 'RelayState' parameter constant.
   */
  RELAY_STATE("RelayState"),
  /**
   * Represents the 'remoteAddr' parameter constant.
   */
  REMOTE_ADDR("remoteAddr"),
  /**
   * Represents the 'remoteUser' parameter constant.
   */
  REMOTE_USER("remoteUser"),
  
  /**
   * Represents the 'SAMLRequest' parameter constant.
   */
  SAML_REQUEST("SAMLRequest"),
  /**
   * Represents the 'SAMLResponse' parameter constant.
   */
  SAML_RESPONSE("SAMLResponse"),
  /**
   * Represents the 'SAMLResponse' parameter constant.
   */
  SAML_ARTIFACT("SAMLArtifact"),
  /**
   * Represents the 'SAMLFail' parameter constant.
   */
  SAML_TOKEN_FAIL("SAMLFail"),
  /**
   * Represents the 'TokenId' parameter constant.
   */
  SAML_TOKEN_ID("TokenId"),
  /**
   * Represents the 'inResponseTo' parameter constant.
   */
  SAML_IN_RESPONSE_TO("inResponseTo"),
  /**
   * Represents the 'inResponseTo.idp' parameter constant.
   */
  SAML_IN_RESPONSE_TO_IDP("inResponseTo.idp"),
  
  /**
   * Represents the 'SignatureResponse' parameter constant.
   */
  SIGNATURE_RESPONSE("SignatureResponse"),
  
  /**
   * Represents the 'cPepsSession' parameter constant.
   */
  SESSION_ID_URL("cPepsSession"),
  /**
   * Represents the 'spId' parameter constant.
   */
  SP_ID("spId"),
  /**
   * Represents the 'spQaaLevel' parameter constant.
   */
  SP_QAALEVEL("spQaaLevel"),
  /**
   * Represents the 'spUrl' parameter constant.
   */
  SP_URL("spUrl"),
  
  /**
   * Represents the 'allow.derivation.all' parameter constant.
   */
  SPECIFIC_ALLOW_DERIVATION_ALL("allow.derivation.all"),
  /**
   * Represents the ''allow.unknowns parameter constant.
   */
  SPECIFIC_ALLOW_UNKNOWNS("allow.unknowns"),
  /**
   * Represents the 'derivation.date.separator' parameter constant.
   */
  SPECIFIC_DERIVATION_DATE_SEP("derivation.date.separator"),
  /**
   * Represents the 'derivation.month.position' parameter constant.
   */
  SPECIFIC_DERIVATION_MONTH_POS("derivation.month.position"),
  /**
   * Represents the 'derivation.day.position' parameter constant.
   */
  SPECIFIC_DERIVATION_DAY_POS("derivation.day.position"),
  /**
   * Represents the 'derivation.year.position' parameter constant.
   */
  SPECIFIC_DERIVATION_YEAR_POS("derivation.year.position"),
  
  /**
   * sp.authorized.parameters Represents the '' parameter constant.
   */
  SPEPS_AUTHORIZED("sp.authorized.parameters"),
  
  /**
   * Represents the 'spSector' constant value.
   */
  SPSECTOR("spSector"),
  /**
   * Represents the 'spApplication' constant value.
   */
  SPAPPLICATION("spApplication"),
  /**
   * Represents the 'spCountry' constant value.
   */
  SPCOUNTRY("spCountry"),
  /**
   * Represents the 'spInstitution' constant value.
   */
  SPINSTITUTION("spInstitution"),
  /**
   * Represents the 'storkAttribute.number' parameter constant.
   */
  STORK_ATTRIBUTE_NUMBER("storkAttribute.number"),
  /**
   * Represents the 'storkAttributeValue.number' parameter constant.
   */
  STORK_ATTRIBUTE_VALUE_NUMBER("storkAttributeValue.number"),
  
  /**
   * Represents the 'username' parameter constant.
   */
  USERNAME("username"),
  
  /**
   * Represents the 'tooManyParameters' parameter constant.
   */
  TOO_MANY_PARAMETERS("tooManyParameters"),
  /**
   * Represents the 'validation.active' parameter constant.
   */
  VALIDATION_ACTIVE("validation.active"),
  
  /**
   * Represents the 'x-forwarded-for' parameter constant.
   */
  X_FORWARDED_FOR("x-forwarded-for"),
  /**
   * Represents the 'x-forwarded-host' parameter constant.
   */
  X_FORWARDED_HOST("x-forwarded-host"),
  /**
   * Represents the 'XMLResponse' parameter constant.
   */
  XML_RESPONSE("XMLResponse"),

    /**
     * the phase of saml (request or response)
     */
    SAML_PHASE("samlphase"),

    /**
     * http binding to use (either GET or POST)
     */
    BINDING("binding"),
    /**
     * name of parameter which activates binding validation
     */
    VALIDATE_BINDING("validate.binding"),
    ALLOW_REDIRECT_BINDING("allow.redirect.binding"),
    /**
     * whether to sign the assertion in Idp
     */
    RESPONSE_SIGN_ASSERTION("response.sign.assertions"),

  /**
   * name of the session parameter holding the url of an error interceptor (used in ValidationPEPS)
   */
  ERROR_INTERCEPTOR_URL("error.interceptor.url"),

  /**
   * set to true when the http session is created on the SPEPS
   */
  SPEPS_SESSION("speps.session"),

  SPEPS_COUNTRY("SPEPSCountry"),

  METADATA_TIMEOUT("metadata.request.timeout"),
  SPEPS_ACTIVE("active.module.speps"),
  CPEPS_ACTIVE("active.module.cpeps"),
  SPEPS_TRUSTED_SP("trusted.sp.domains"),
  PEPS_HASH_DIGEST_CLASS("hashDigest.className"),
  SP_METADATA_URL("spmetadataurl"),
  EIDAS_SERVICE_LOA("saml.loa"),
  EIDAS_NAMEID_FORMAT("eidas.nameid"),
  /**
   * whether to sign the assertion in Idp
   */
  RESPONSE_ENCRYPT_ASSERTION("response.encryption.mandatory"),
  /**
   * the current http method
   */
  HTTP_METHOD("request.http.method"),
  ;

  private static Set<String> allParameterNames;
  /**
   * Represents the constant's value.
   */
  private String value;
  
  /**
   * Solo Constructor.
   * 
   * @param nValue The Constant value.
   */
  PEPSParameters(final String nValue) {
    this.value = nValue;
    PEPSParameters.registerName(nValue);
  }

    /**
     *
     * @param nValue the name of the parameter to register
     */
  private static void registerName(String nValue){
      if(allParameterNames ==null){
          allParameterNames =new HashSet<String>();
      }
      allParameterNames.add(nValue);
  }

    /**
     *
     * @return all registered names
     */
  public static Set<String> getNames(){
    return new HashSet<String>(allParameterNames);
  }
  
  /**
   * Return the Constant Value.
   * 
   * @return The constant value.
   */
  public String toString() {
    return value;
  }
}
