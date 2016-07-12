/**
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
package eu.eidas.auth.commons;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class is a bean used to store the information relative to the
 * EIDASAuthnRequest (SAML Token Request).
 * 
 */
public final class EIDASAuthnRequest implements Serializable, Cloneable {

  /** The Constant serialVersionUID. */
  private static final long serialVersionUID = 4778480781609392750L;
    public static final String BINDING_POST="POST";
  public static final String BINDING_REDIRECT="GET";
  public static final String BINDING_EMPTY="EMPTY";
  public static final String NAMEID_FORMAT_PERSISTENT="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
  public static final String NAMEID_FORMAT_TRANSIENT="urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
  public static final String NAMEID_FORMAT_UNSPECIFIED="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
  public static final Set<String> SUPPORTED_NAMEID_FORMATS=new HashSet<String>();
  static
  {
    SUPPORTED_NAMEID_FORMATS.add(NAMEID_FORMAT_PERSISTENT);
    SUPPORTED_NAMEID_FORMATS.add(NAMEID_FORMAT_TRANSIENT);
    SUPPORTED_NAMEID_FORMATS.add(NAMEID_FORMAT_UNSPECIFIED);
  }

  /**
   * Logger object.
   */
  private static final Logger LOG = LoggerFactory.getLogger(EIDASAuthnRequest.class
    .getName());
  
  /** The samlId. */
  private String samlId;
  
  /** The assertion consumer service url. */
  private String serviceURL;
  
  /** The destination. */
  private String destination;
  
  /** The provider name. */
  private String providerName;
  
  /** The distinguished name. */
  private String distinguishedName;
  
  /** The e id sector share. */
  private boolean eIDSectorShare;
  
  /** The e id cross sector share. */
  private boolean eIDCrossSectorShare;
  
  /** The e id cross border share. */
  private boolean eIDCrossBorderShare;
  
  /** The personal attribute list. */
  private IPersonalAttributeList attributeList = new PersonalAttributeList();
  
  /** The qaa. */
  private int qaa;
  
  /** The token saml. */
  private byte[] tokenSaml = new byte[0];
  
  /** The issuer. */
  private String issuer;
  
  /** The service provider sector. */
  private String spSector;
  
  /** The service provider institution. */
  private String spInstitution;
  
  /** The service provider application. */
  private String spApplication;
  
  /** The service provider country. */
  private String spCountry;
  
  /** The country. */
  private String country;
  
  /** The citizen country code. */
  private String citizenCountry;
  
  /** The Service Provider ID. */
  private String sPID;
  
  /** The Alias used at the keystore for saving this certificate. */
  private String alias;

  /** the protocol binding - either POST or GET/Redirect*/
  private String binding;

  /** original issuer of the request (proxied by the current emitter) */
  private String originalIssuer;

  private String spType;
  /**
   * level of assurance value
   */
  private String eidasLoA;

  /**
   * level of assurance comparison type
   */
  private String eidasLoACompareType;

  /**
   * the format of the nameid
   */
  private String eidasNameidFormat;

  /**
   * the name of the message format this request belongs to.
   */
  private String messageFormatName;

  /**
   * Gets the SP's Certificate Alias.
   * 
   * @return alias The SP's Certificate Alias.
   */
  public String getAlias() {
    return alias;
  }
  
  /**
   * Sets the SP's Certificate Alias.
   * 
   * @param nAlias The SP's Certificate Alias.
   */
  public void setAlias(final String nAlias) {
    this.alias = nAlias;
  }
  
  /**
   * Gets the SP ID.
   * 
   * @return sPID The SP ID.
   */
  public String getSPID() {
    return sPID;
  }
  
  /**
   * Sets the SP ID.
   * 
   * @param sPId The new sp samlId.
   */
  public void setSPID(final String sPId) {
    this.sPID = sPId;
  }
  
  /**
   * Gets the citizen country code.
   * 
   * @return The citizen country code value.
   */
  public String getCitizenCountryCode() {
    return citizenCountry;
  }
  
  /**
   * Sets the citizen country code.
   * 
   * @param countryCode the new citizen country code value.
   */
  public void setCitizenCountryCode(final String countryCode) {
    this.citizenCountry = countryCode;
  }
  
  /**
   * Gets the sp country.
   * 
   * @return The sp country value.
   */
  public String getSpCountry() {
    return spCountry;
  }
  
  /**
   * Sets the sp country.
   * 
   * @param sPCountry the new sp country value.
   */
  public void setSpCountry(final String sPCountry) {
    this.spCountry = sPCountry;
  }
  
  /**
   * Gets the issuer.
   * 
   * @return The issuer value.
   */
  public String getIssuer() {
    return issuer;
  }
  
  /**
   * Sets the issuer.
   * 
   * @param samlIssuer the new issuer value.
   */
  public void setIssuer(final String samlIssuer) {
    this.issuer = samlIssuer;
  }
  
  /**
   * Gets the SAML Token.
   * 
   * @return The SAML Token value.
   */
  public byte[] getTokenSaml() {
    return tokenSaml.clone();
  }
  
  /**
   * Sets the SAML Token.
   * 
   * @param samlToken The new SAML Token value.
   */
  public void setTokenSaml(final byte[] samlToken) {
    if (samlToken != null) {
      this.tokenSaml = samlToken.clone();
    }
  }
  
  /**
   * Gets the country.
   * 
   * @return The country value.
   */
  public String getCountry() {
    return country;
  }
  
  /**
   * Sets the country.
   * 
   * @param nCountry the new country value.
   */
  public void setCountry(final String nCountry) {
    this.country = nCountry;
  }
  
  /**
   * Getter for the qaa value.
   * 
   * @return The qaa value value.
   */
  public int getQaa() {
    return qaa;
  }
  
  /**
   * Setter for the qaa value.
   * 
   * @param qaaLevel The new qaa value.
   */
  public void setQaa(final int qaaLevel) {
    this.qaa = qaaLevel;
  }
  
  /**
   * Getter for the serviceURL value.
   * 
   * @return The serviceURL value.
   */
  public String getAssertionConsumerServiceURL() {
    return serviceURL;
  }
  
  /**
   * Setter for the serviceURL value.
   * 
   * @param newServiceURL the assertion consumer service URL.
   */
  public void setAssertionConsumerServiceURL(final String newServiceURL) {
    this.serviceURL = newServiceURL;
  }
  
  /**
   * Getter for the destination value.
   * 
   * @return The destination value.
   */
  public String getDestination() {
    return destination;
  }
  
  /**
   * Setter for the destination value.
   * 
   * @param destinationArg the new destination value.
   */
  public void setDestination(final String destinationArg) {
    this.destination = destinationArg;
  }
  
  /**
   * Getter for the samlId value.
   * 
   * @return The samlId value.
   */
  public String getSamlId() {
    return samlId;
  }
  
  /**
   * Setter for the samlId value.
   * 
   * @param newSamlId the new samlId value.
   */
  public void setSamlId(final String newSamlId) {
    this.samlId = newSamlId;
  }
  
  /**
   * Getter for the providerName value.
   * 
   * @return The provider name value.
   */
  public String getProviderName() {
    return providerName;
  }
  
  /**
   * Setter for the providerName value.
   * 
   * @param samlProvider the provider name value.
   */
  public void setProviderName(final String samlProvider) {
    this.providerName = samlProvider;
  }
  
  /**
   * Getter for the attributeList value.
   * 
   * @return The attributeList value.
   * 
   * @see IPersonalAttributeList
   */
  public IPersonalAttributeList getPersonalAttributeList() {
      IPersonalAttributeList personnalAttributeList = null;
      try {
          personnalAttributeList = (IPersonalAttributeList) attributeList.clone();
      } catch (CloneNotSupportedException e1) {
          LOG.trace("[PersonalAttribute] Nothing to do. {}", e1);
      }
      return personnalAttributeList;
  }
  
  /**
   * Setter for the attributeList value.
   * 
   * @param attrList the personal attribute list value.
   * 
   * @see IPersonalAttributeList
   */
  public void setPersonalAttributeList(final IPersonalAttributeList attrList) {
    if (attrList != null) {
      this.attributeList = attrList;
    }
  }
  
  /**
   * Getter for the distinguishedName value.
   * 
   * @return The distinguishedName value.
   */
  public String getDistinguishedName() {
    return distinguishedName;
  }
  
  /**
   * Setter for the distinguishedName value.
   * 
   * @param certDN the distinguished name value.
   */
  public void setDistinguishedName(final String certDN) {
    this.distinguishedName = certDN;
  }
  
  /**
   * Gets the service provider sector.
   * 
   * @return The service provider sector value.
   */
  public String getSpSector() {
    return spSector;
  }
  
  /**
   * Sets the service provider sector.
   * 
   * @param samlSPSector the new service provider sector value.
   */
  public void setSpSector(final String samlSPSector) {
    this.spSector = samlSPSector;
  }
  
  /**
   * Gets the service provider institution.
   * 
   * @return The service provider institution value.
   */
  public String getSpInstitution() {
    return spInstitution;
  }
  
  /**
   * Sets the service provider institution.
   * 
   * @param samlSPInst the new service provider institution value.
   */
  public void setSpInstitution(final String samlSPInst) {
    this.spInstitution = samlSPInst;
  }
  
  /**
   * Gets the service provider application.
   * 
   * @return The service provider application value.
   */
  public String getSpApplication() {
    return spApplication;
  }
  
  /**
   * Sets the service provider application.
   * 
   * @param samlSPApp the new service provider application value.
   */
  public void setSpApplication(final String samlSPApp) {
    this.spApplication = samlSPApp;
  }
  
  /**
   * Checks if is eId sector share.
   * 
   * @return true, if is eId sector share.
   */
  public boolean isEIDSectorShare() {
    return eIDSectorShare;
  }
  
  /**
   * Sets the eId sector share.
   * 
   * @param eIdSectorShare the new eId sector share value.
   */
  public void setEIDSectorShare(final boolean eIdSectorShare) {
    this.eIDSectorShare = eIdSectorShare;
  }
  
  /**
   * Checks if is eId cross sector share.
   * 
   * @return true, if is eId cross sector share.
   */
  public boolean isEIDCrossSectorShare() {
    return eIDCrossSectorShare;
  }
  
  /**
   * Sets the eId cross sector share.
   * 
   * @param eIdCrossSectorShare the new eId cross sector share value.
   */
  public void setEIDCrossSectorShare(final boolean eIdCrossSectorShare) {
    this.eIDCrossSectorShare = eIdCrossSectorShare;
  }
  
  /**
   * Checks if is eId cross border share.
   * 
   * @return true, if is eId cross border share.
   */
  public boolean isEIDCrossBorderShare() {
    return eIDCrossBorderShare;
  }
  
  /**
   * Sets the eId cross border share.
   * 
   * @param eIdCrossBorderShare the new eId cross border share value.
   */
  public void setEIDCrossBorderShare(final boolean eIdCrossBorderShare) {
    this.eIDCrossBorderShare = eIdCrossBorderShare;
  }

    public String getBinding() {
        if(null==binding) {
          return BINDING_POST;
        }
        return binding;
    }

    public void setBinding(String bindingArg) {
        this.binding = bindingArg==null?null:bindingArg.toUpperCase();
    }

  public String getOriginalIssuer() {
    return originalIssuer;
  }

  public void setOriginalIssuer(String originalIssuerArg) {
    this.originalIssuer = originalIssuerArg;
  }

  public String getSPType() {
    return spType;
  }

  public void setSPType(String spTypeArg) {
    this.spType = spTypeArg;
  }

  public String getEidasLoA() {
    return eidasLoA;
  }

  public void setEidasLoA(String eidasLoAArg) {
    this.eidasLoA = eidasLoAArg;
  }

  public String getEidasNameidFormat() {
    return eidasNameidFormat;
  }

  public void setEidasNameidFormat(String eidasNameidFormatArg) {
    this.eidasNameidFormat = eidasNameidFormatArg;
  }

  public String getMessageFormatName() {
    return messageFormatName;
  }

  public void setMessageFormatName(String messageFormatNameArg) {
    this.messageFormatName = messageFormatNameArg;
  }

  public String getEidasLoACompareType() {
    return eidasLoACompareType;
  }

  public void setEidasLoACompareType(String eidasLoACompareTypeArg) {
    this.eidasLoACompareType = eidasLoACompareTypeArg;
  }

  /**
   * Returns a copy of this <tt>EIDASAuthnRequest</tt> instance.
   * 
   * @return The copy of this EIDASAuthnRequest.
   * @throws CloneNotSupportedException on clone exception
   */
  @Override
  public Object clone() throws CloneNotSupportedException{
    EIDASAuthnRequest eidasAuthnReq = null;

      try {
          eidasAuthnReq = (EIDASAuthnRequest) super.clone();
          eidasAuthnReq.setPersonalAttributeList(getPersonalAttributeList());
          eidasAuthnReq.setTokenSaml(getTokenSaml());
          eidasAuthnReq.setMessageFormatName(messageFormatName);
          eidasAuthnReq.setSPType(getSPType());
      } catch (final CloneNotSupportedException e) {
          LOG.trace("[PersonalAttribute] Nothing to do.{}", e);
          throw e;
      }

    return eidasAuthnReq;
  }
    /**
     * Returns the string representation of a EIDASAuthnRequest
     * Do not display tokenSaml & attribute list
     */
    @Override
    public String toString() {
        StringBuilder stringBuilder = new StringBuilder(getClass().getSimpleName()).append(" [")
                .append("samlId             ").append(samlId).append(",\n")
                .append("destination        ").append(destination).append(",\n")
                .append("providerName       ").append(providerName).append(",\n")
                .append("distinguishedName  ").append(distinguishedName).append(",\n")
                .append("issuer             ").append(issuer).append(",\n")
                .append("sPID               ").append(sPID).append(",\n")
                .append("spApplication      ").append(spApplication).append(",\n")
                .append("spCountry          ").append(spCountry).append(",\n")
                .append("citizenCountry     ").append(citizenCountry).append(",\n")
                .append("serviceURL         ").append(serviceURL).append(",\n")
                .append("alias              ").append(alias).append(",\n")
                .append("binding            ").append(binding).append(",\n")
                .append("]");
        return stringBuilder.toString();
    }
}
