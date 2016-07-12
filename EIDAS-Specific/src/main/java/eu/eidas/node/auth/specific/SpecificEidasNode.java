/*
 * This work is Open Source and licensed by the European Commission under the
 * conditions of the European Public License v1.1 
 *  
 * (http://www.osor.eu/eupl/european-union-public-licence-eupl-v.1.1); 
 * 
 * any use of this file implies acceptance of the conditions of this license. 
 * Unless required by applicable law or agreed to in writing, software distributed 
 * under the License is distributed on an "AS IS" BASIS,  WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the 
 * specific language governing permissions and    limitations under the License.
 */
package eu.eidas.node.auth.specific;

import java.util.*;

import eu.eidas.auth.commons.*;
import eu.eidas.auth.commons.exceptions.*;
import eu.eidas.auth.engine.EIDASSAMLEngine;
import eu.eidas.auth.engine.core.EidasSAMLEngineFactoryI;
import eu.eidas.auth.engine.core.SAMLExtensionFormat;
import eu.eidas.auth.specific.IAUService;
import eu.eidas.auth.specific.ICheckAttributeValue;
import eu.eidas.auth.specific.IDeriveAttribute;
import eu.eidas.auth.specific.INormaliseValue;
import eu.eidas.auth.specific.ITranslatorService;
import eu.eidas.engine.exceptions.EIDASSAMLEngineException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class is specific and should be modified by each member state if they
 * want to use any different settings.
 * 
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com, hugo.magalhaes@multicert.com
 */
@SuppressWarnings("PMD")
public final class SpecificEidasNode implements IAUService, ITranslatorService {
   
   /**
    * Logger object.
    */
   private static final Logger LOG = LoggerFactory.getLogger(SpecificEidasNode.class
      .getName());
   private static final String NOT_AVAILABLE_VALUE="NOT AVAILABLE";
   private static final String NOT_AVAILABLE_COUNTRY="NA";
   
   /**
    * Specific configurations.
    */
   private IEIDASConfigurationProxy specificProps;
   
   private Map<String, IDeriveAttribute> derivedImpls;
   
   private Map<String, INormaliseValue> normaliseImpls;
   
   private Map<String, ICheckAttributeValue> validateImpls;

    private Properties serviceProperties;
    private EidasSAMLEngineFactoryI samlEngineFactory;
   private String serviceMetadataUrl;
   private String serviceRequesterMetadataUrl;
   private Boolean serviceMetadataActive;

    public EidasSAMLEngineFactoryI getSamlEngineFactory() {
        return samlEngineFactory;
    }

    public void setSamlEngineFactory(EidasSAMLEngineFactoryI samlEngineFactory) {
        this.samlEngineFactory = samlEngineFactory;
    }
    public Properties getServiceProperties() {
        return serviceProperties;
    }

    public void setServiceProperties(Properties nodeProps) {
        this.serviceProperties = nodeProps;
    }

   private String samlEngine;

    public String getSamlEngine() {
        return samlEngine;
    }

    public void setSamlEngine(String samlEngine) {
        this.samlEngine = samlEngine;
    }

    /**
    * {@inheritDoc}
    */
   public byte[]
      prepareCitizenAuthentication(final IPersonalAttributeList personalList,
         final Map<String, Object> parameters,
         final Map<String, Object> attrHeaders,
         final IEIDASSession session) {

      final String destination =
         (String) parameters.get(EIDASParameters.IDP_URL.toString());
      final String assertion =
         (String) parameters.get(EIDASParameters.EIDAS_SERVICE_CALLBACK.toString());

      return this.generateAuthenticationRequest(
              destination,
              assertion,
              (Integer) parameters.get(EIDASParameters.QAALEVEL.toString()),
              (String) parameters.get(EIDASParameters.EIDAS_SERVICE_LOA.toString()),
              personalList,
              session,
              (String) parameters.get(EIDASParameters.EIDAS_NAMEID_FORMAT.toString()));
   }
   
   /**
    * {@inheritDoc}
    */
   public IPersonalAttributeList
      authenticateCitizen(final IPersonalAttributeList personalList,
         final Map<String, Object> parameters,
         final Map<String, Object> attrHeaders) {

      /**
       * 
       * This method is used for internally authenticating the citizen. It is
       * not implemented and it is supposed to be specific. The member states
       * who wish to use an internal identity provider should implement this
       * method. Otherwise, it can be removed.
       * 
       */
      
      final IPersonalAttributeList pal = new PersonalAttributeList(2);
      
      PersonalAttribute pAttr = new PersonalAttribute();
      pAttr.setName("givenName");
      List<String> value = new ArrayList<String>();
      value.add("Jose Esteves");
      pAttr.setValue(value);
      pAttr.setIsRequired(true);
      pal.add(pAttr);
      
      pAttr = new PersonalAttribute();
      pAttr.setName("dateOfBirth");
      value = new ArrayList<String>();
      value.add("19651021");
      pAttr.setValue(value);
      pAttr.setIsRequired(false);
      pal.add(pAttr);
      
      return pal;
   }
   
   /**
    * {@inheritDoc}
    */
   public boolean prepareAPRedirect(final IPersonalAttributeList personalList,
      final Map<String, Object> parameters,
      final Map<String, Object> attrHeaders,
      final IEIDASSession session) {

      final String apId = (String) session.get(EIDASParameters.AP_ID.toString());
      final int apNumber =
         Integer.parseInt(specificProps.getEidasParameterValue(EIDASParameters.AP_NUMBER
                 .toString()));
      
      if (apNumber <= 0) {
         LOG.debug("There are no APs");
         return false;
      }
      
      if (apId != null) {
         final int currApNumber =
            Integer.parseInt(apId.split(EIDASValues.AP.toString())[1]);
         if (currApNumber < apNumber) {
            LOG.debug("Current AP : ap"
               + (currApNumber));
            LOG.debug("Next AP : ap"
               + (currApNumber + 1));
            session.put(EIDASParameters.AP_ID.toString(), EIDASValues.AP
               .toString()
               + (currApNumber + 1));
            session.put(EIDASParameters.AP_URL.toString(), specificProps
               .getEidasParameterValue(EIDASValues.AP.url(currApNumber + 1)));
            LOG.trace("True");
            return true;
         } else {
            LOG.debug("Current AP : ap"
               + (currApNumber));
            LOG.debug("No more APs");
            session.remove(EIDASParameters.AP_ID.toString());
            session.remove(EIDASParameters.AP_URL.toString());
            LOG.trace("False");
            return false;
         }
      } else {
         LOG.debug("Saving AP: ap1");
         session.put(
            EIDASParameters.AP_ID.toString(),
            EIDASValues.AP.toString() + 1);
         session.put(EIDASParameters.AP_URL.toString(), specificProps
            .getEidasParameterValue(EIDASValues.AP.url(1)));
         LOG.trace("True");
         return true;
      }
   }
   
   /**
    * {@inheritDoc}
    */
   public IPersonalAttributeList
      getAttributesFromAttributeProviders(final IPersonalAttributeList personalList,
         final Map<String, Object> parameters,
         final Map<String, Object> attrHeaders) {

      /**
       * 
       * This method is used for internally filling the Personal Attribute List
       * with values. It is not implemented and it is supposed to be specific.
       * The member states who wish to use an internal attribute provider should
       * implement this method. Otherwise, it can be removed.
       * 
       */
      throw new UnsupportedOperationException("Code not implemented");
   }
   
   /**
    * {@inheritDoc}
    */
   public boolean
      getAttributesWithVerification(final IPersonalAttributeList personalList,
         final Map<String, Object> parameters,
         final Map<String, Object> attrHeaders,
         final IEIDASSession session,
         final String auProcessID) {

      return true;
   }
   
   /**
    * {@inheritDoc}
    */
   public IPersonalAttributeList
      normaliseAttributeNamesTo(final IPersonalAttributeList personalList) {

      final IPersonalAttributeList pal =
         new PersonalAttributeList(personalList.size());
      
      final boolean allowUnknowns =
         Boolean.valueOf(specificProps
            .getEidasParameterValue(EIDASParameters.SPECIFIC_ALLOW_UNKNOWNS.toString()));
      
      final int nNames =
         Integer.parseInt(specificProps
            .getEidasParameterValue(EIDASParameters.SPECIFIC_ATTRIBUTE_NUMBER.toString()));
      final Map<String, String> attributes = new HashMap<String, String>();
      
      for (int i = 1; i <= nNames; i++) {
         final String attrName =
            specificProps.getEidasParameterValue(EIDASValues.EIDAS_ATTRIBUTE.index(i));
         final String specificName =
            specificProps.getEidasParameterValue(EIDASValues.EIDAS_ATTRIBUTE.name(i));
         attributes.put(attrName, specificName);
      }
      
      for (final PersonalAttribute pa : personalList) {
         LOG.trace("Normalizing attribute "
            + pa.getName());
         final String normVal = attributes.get(pa.getName());
         if (normVal != null) {
            LOG.trace("Found " + normVal);
            final PersonalAttribute tPa = new PersonalAttribute();
            tPa.setIsRequired(pa.isRequired());
            tPa.setValue(pa.getValue());
            tPa.setName(normVal);
            tPa.setStatus(pa.getStatus());
            tPa.setComplexValue(pa.getComplexValue());
            pal.put(normVal, tPa);
         } else {
            LOG.trace("Not found!");
            if (allowUnknowns) {
               pal.put(pa.getName(), pa);
            } else {
               LOG.info("ERROR Attribute is unknown to this service: "
                       + pa.getName());
               throw new InvalidParameterEIDASException(
                  EIDASUtil.getConfig(EIDASErrors.INVALID_ATTRIBUTE_LIST
                     .errorCode()),
                  EIDASUtil.getConfig(EIDASErrors.INVALID_ATTRIBUTE_LIST
                     .errorMessage()));
            }
         }
      }
      
      return pal;
   }
   
   /**
    * {@inheritDoc}
    */
   public IPersonalAttributeList
      normaliseAttributeNamesFrom(final IPersonalAttributeList personalList) throws SecurityEIDASException {

      LOG.trace("On normaliseAttributeNamesFrom method");
      
      final int nNames =
         Integer.parseInt(specificProps
            .getEidasParameterValue(EIDASParameters.SPECIFIC_ATTRIBUTE_NUMBER.toString()));
      final Map<String, String> attributes = new HashMap<String, String>();
      
      for (int i = 1; i <= nNames; i++) {
         final String specificName =
            specificProps.getEidasParameterValue(EIDASValues.EIDAS_ATTRIBUTE.name(i));
         final String attrName =
            specificProps.getEidasParameterValue(EIDASValues.EIDAS_ATTRIBUTE.index(i));
         if (!attributes.containsKey(specificName)) {
            attributes.put(specificName, attrName);
         }
      }
      
      final IPersonalAttributeList personalAttributeList =
         new PersonalAttributeList(personalList.size());
      
      for (final PersonalAttribute pa : personalList) {
         LOG.trace("Normalizing attribute "
            + pa.getName());
         final String normVal = attributes.get(pa.getName());
         
         if (normVal == null) {
            LOG.debug("Not found!");
            personalAttributeList.put(pa.getName(), pa);
         } else {
            LOG.debug("Found " + normVal);
            pa.setName(normVal);
            personalAttributeList.put(normVal, pa);
         }
      }
      
      LOG.trace("End");
      return personalAttributeList;
   }
   
   /**
    * {@inheritDoc}
    */
   public IPersonalAttributeList
      deriveAttributeFrom(final IPersonalAttributeList personalList) {

      final int nNames =
         Integer.parseInt(specificProps
            .getEidasParameterValue(EIDASParameters.DERIVE_ATTRIBUTE_NUMBER.toString()));
      
      final Map<String, String> derivations = new HashMap<String, String>();
      for (int i = 1; i <= nNames; i++) {
         final String derivedId =
            specificProps.getEidasParameterValue(EIDASValues.DERIVE_ATTRIBUTE.index(i));
         final String derivedName =
            specificProps.getEidasParameterValue(EIDASValues.DERIVE_ATTRIBUTE.name(i));
         if (!derivations.containsKey(derivedId)) {
            derivations.put(derivedId, derivedName);
         }
      }
      
      final IPersonalAttributeList derivedList = new PersonalAttributeList();
      
      for (final PersonalAttribute pa : personalList) {
         final String attrName = pa.getName();
         LOG.debug("Deriving:" + attrName);
         
         final String derivedName = derivations.get(attrName);
         if (derivedName != null) {
            LOG.debug("Replacing "
               + attrName + " with " + derivedName);
            final PersonalAttribute tPa = new PersonalAttribute();
            tPa.setIsRequired(pa.isRequired());
            tPa.setName(derivedName);
            if (!derivedList.containsKey(derivedName)) {
               derivedList.put(derivedName, tPa);
            }
         } else {
            LOG.debug("Keeping " + attrName);
            if (!derivedList.containsKey(attrName)) {
               derivedList.put(attrName, pa);
            }
         }
      }
      
      return derivedList;
   }
   
   /**
    * {@inheritDoc}
    */
   public IPersonalAttributeList
      deriveAttributeTo(final IEIDASSession session,
         final IPersonalAttributeList modifiedList) {

      final IPersonalAttributeList originalList =
         ((EIDASAuthnRequest) session.get(EIDASParameters.AUTH_REQUEST
            .toString())).getPersonalAttributeList();
      
      final int nNames =
         Integer.parseInt(specificProps
            .getEidasParameterValue(EIDASParameters.DERIVE_ATTRIBUTE_NUMBER.toString()));
      
      Map<String, String> derivatedAttrs = new HashMap<String, String>(nNames);
      for (int i = 1; i <= nNames; i++) {
         final String derivedId =
            specificProps.getEidasParameterValue(EIDASValues.DERIVE_ATTRIBUTE.index(i));
         final String derivedName =
            specificProps.getEidasParameterValue(EIDASValues.DERIVE_ATTRIBUTE.name(i));
         derivatedAttrs.put(derivedId, derivedName);
      }
      
      IPersonalAttributeList attrList = new PersonalAttributeList();
      for (PersonalAttribute pa : originalList) {
         final String derivedId = pa.getName();
         if (derivatedAttrs.containsKey(derivedId)
            && modifiedList.containsKey(derivatedAttrs.get(derivedId))) {
            final String derivedName = derivatedAttrs.get(derivedId);
            LOG.debug("Deriving: "
               + derivedId + " to " + derivedName);
            final PersonalAttribute mPa = new PersonalAttribute();
            mPa.setValue(modifiedList.get(derivedName).getValue());
            mPa.setIsRequired(pa.isRequired());
            mPa.setName(derivedId);
            mPa.setFullName(pa.getFullName());
            mPa.setStatus(modifiedList.get(derivedName).getStatus());
            derivedImpls.get(derivedId)
               .deriveAttributeToData(mPa, session);
            attrList.put(derivedId, mPa);
         } else {
            attrList.put(derivedId, pa);
         }
      }
      return attrList;
   }
   
   /**
    * {@inheritDoc}
    */
   public IPersonalAttributeList
      normaliseAttributeValuesTo(final IPersonalAttributeList personalList) {

       PersonalAttributeList personalAttributeList = null;
       try {
           personalAttributeList = (PersonalAttributeList) personalList.clone();
       } catch (CloneNotSupportedException e) {
           LOG.trace("[PersonalAttribute] Nothing to do.{}", e);
       }
       if (personalAttributeList != null) {
           for (final PersonalAttribute personalAttribute : personalAttributeList) {
             LOG.debug("Attribute "
                + personalAttribute.getName());
             if (normaliseImpls.containsKey(personalAttribute.getName())) {
                LOG.debug("Start Attribute's ("
                   + personalAttribute.getName() + ") normalisation.");
                if (!personalAttribute.isEmptyValue()) {
                   final INormaliseValue normaliseValue =
                      normaliseImpls.get(personalAttribute.getName());
                   normaliseValue.normaliseAttributeValueToFormat(personalAttribute);
                   personalList.put(personalAttribute.getName(), personalAttribute);
                }
             }
          }
          Set<String> aliasNumbers=new HashSet<String>();
          for (final PersonalAttribute personalAttribute : personalAttributeList) {
             if(personalAttributeList.isNumberAlias(personalAttribute.getName())) {
                 aliasNumbers.add(personalAttribute.getName());
             }
          }
          for( String aliasKey:aliasNumbers) {
              personalAttributeList.remove(aliasKey);
          }
       }
      
      return personalList;
   }
   
   /**
    * {@inheritDoc}
    */
   public EIDASAuthnResponse
      processAuthenticationResponse(final byte[] samlToken,
         final IEIDASSession session) {

      final EIDASSAMLEngine engine = getSamlEngineFactory().getEngine(getSamlEngine(), getServiceProperties());
      EIDASAuthnResponse authnResponse;
      try {
          EIDASAuthnRequest request=(EIDASAuthnRequest) session.get(EIDASParameters.AUTH_REQUEST.toString());
          final String respondTo = request.getCitizenCountryCode();
          engine.setCountryRespondTo(respondTo);
          engine.initRequestedAttributes(request.getPersonalAttributeList());
          authnResponse = engine.validateEIDASAuthnResponse(samlToken, (String) session.get(EIDASParameters.REMOTE_ADDR.toString()), 0);    // Skew time from IDP is set to 0
      } catch (final EIDASSAMLEngineException e) {
          String code="0";
          String message="Validation Autentication Response.";
         EIDASErrors err=null;
          if (EIDASErrors.isErrorCode(e.getErrorCode())) {
              err=EIDASErrors.fromCode(e.getErrorCode());
              message=EIDASUtil.getConfig(err.errorMessage());
              code=EIDASUtil.getConfig(err.errorCode());
          }
          if(!session.containsKey(EIDASParameters.ERROR_REDIRECT_URL.toString())) {
             session.put(EIDASParameters.ERROR_REDIRECT_URL.toString(), session.get(EIDASParameters.SP_URL.toString()));
          }
         LOG.info("ERROR : Error validating SAML Autentication Response from IdP", e.getMessage());
         LOG.debug("ERROR : Error validating SAML Autentication Response from IdP", e);
         if(err!=null && !err.isShowToUser()){
            throw new EIDASServiceException("", code, message, e, EIDASUtil.getConfig(EIDASErrors.IDP_SAML_RESPONSE.errorCode()), EIDASUtil.getConfig(EIDASErrors.IDP_SAML_RESPONSE.errorMessage()));
         }else {
            throw new EIDASServiceException("", code, message, e);
         }
      }finally{
         if(engine!=null) {
            getSamlEngineFactory().releaseEngine(engine);
         }
      }
      
      return authnResponse;
   }
   
   /**
    * {@inheritDoc}
    */
   public byte[] generateErrorAuthenticationResponse(final String inResponseTo,
      final String issuer,
      final String assertionConsumerServiceURL,
      final String code,
      final String subcode,
      final String message,
      final String ipUserAddress) {

      final EIDASSAMLEngine engine = getSamlEngineFactory().getEngine(getSamlEngine(), getServiceProperties());
      
      EIDASAuthnResponse error = new EIDASAuthnResponse();
      try {
         // create SAML token
         final EIDASAuthnRequest request = new EIDASAuthnRequest();
         request.setSamlId(inResponseTo);
         request.setIssuer(issuer);
         request.setAssertionConsumerServiceURL(assertionConsumerServiceURL);
         error.setStatusCode(code);
         error.setSubStatusCode(subcode);
         error.setMessage(message);
         error = engine.generateEIDASAuthnResponseFail(request, error, ipUserAddress, false);
      } catch (final EIDASSAMLEngineException e) {
         LOG.info("ERROR : Error generating SAMLToken", e.getMessage());
         LOG.debug("ERROR : Error generating SAMLToken",e);
         throw new InternalErrorEIDASException(
            "0", "Error generating SAMLToken", e);
      }
      getSamlEngineFactory().releaseEngine(engine);
      return error.getTokenSaml();
   }

    private boolean haveExpectedName(final IPersonalAttributeList original, String paName, int arraySize){
        boolean attrNotFound = true;
        for (int i = 1; i <= arraySize; i++) {
            final String derivedId =
                    specificProps.getEidasParameterValue(EIDASValues.DERIVE_ATTRIBUTE.index(i));
            final String derivedName =
                    specificProps.getEidasParameterValue(EIDASValues.DERIVE_ATTRIBUTE.name(i));
            if (paName.equals(derivedName)
                    && original.containsKey(derivedId)) {
                attrNotFound = false;
            }
        }
        return attrNotFound;
    }
   /**
    * {@inheritDoc}
    */
   public boolean
      comparePersonalAttributeLists(final IPersonalAttributeList original,
         final IPersonalAttributeList modified) {

      if (original == null || modified == null) {
         LOG.info("ERROR : At least one list is null!");
         return false;
      }
      
      final int nNames =
         Integer.parseInt(specificProps
            .getEidasParameterValue(EIDASParameters.DERIVE_ATTRIBUTE_NUMBER.toString()));

      for (final PersonalAttribute pa : modified) {
          boolean attrNotFound = true;
         if (!(original.containsKey(pa.getName()))) {
             attrNotFound=haveExpectedName(original, pa.getName(), nNames);
            if (attrNotFound) {
               LOG.info("ERROR : Element is not present on original list: "
                       + pa.getName());
               return false;
            }
         }
      }
      
      return true;
   }
   
   /**
    * {@inheritDoc}
    */
   public boolean checkAttributeValues(final EIDASAuthnRequest authData) {

      final int nNames =
         Integer.parseInt(specificProps
            .getEidasParameterValue(EIDASParameters.ATTR_VALUE_NUMBER.toString()));
      
      final IPersonalAttributeList pal = authData.getPersonalAttributeList();
      
      for (int i = 1; i <= nNames; i++) {
         final String attrName =
            specificProps.getEidasParameterValue(EIDASValues.ATTRIBUTE.index(i));
         final PersonalAttribute pAttr = pal.get(attrName);
         
         if (pAttr != null && !pAttr.isEmptyValue()) {
            final String value =
               specificProps.getEidasParameterValue(EIDASValues.ATTRIBUTE.value(i));
            if (!getValidateImpls().get(attrName)
               .checkValue(pAttr.getValue(), value)) {
               LOG.info("ERROR : Verification failed for attribute " + attrName);
               return false;
            }
         }
      }
      
      return true;
   }
   
   /**
    * Generates a SAML Request.
    * 
    * @param destination The URL of destination.
    * @param assertion The URL to return in case of error.
    * @param qaaLevel The QAA Level.
    * @param personalList The list of personal attributes.
    * @param session The current session.
    * 
    * @return byte[] containing the SAML Request.
    */
   private byte[] generateAuthenticationRequest(final String destination,
      final String assertion,
      final int qaaLevel, final String eidasLoa,
      final IPersonalAttributeList personalList,
      final IEIDASSession session, final String eidasNameidFormat) {

      final EIDASSAMLEngine engine = getSamlEngineFactory().getEngine(getSamlEngine(), getServiceProperties());

      EIDASAuthnRequest authnRequest = new EIDASAuthnRequest();
      
      final String providerId = EIDASValues.EIDAS_SERVICE.toString();
      
      try {
          final EIDASAuthnRequest sessionRequest = (EIDASAuthnRequest)session.get(EIDASParameters.AUTH_REQUEST.toString());

          engine.setCountryResponseFrom(sessionRequest.getCitizenCountryCode());

          // generate authentication request
          authnRequest.setSpSector(NOT_AVAILABLE_VALUE);
          authnRequest.setSpInstitution(NOT_AVAILABLE_VALUE);
          authnRequest.setSpApplication(NOT_AVAILABLE_VALUE);

          authnRequest.setSpCountry(NOT_AVAILABLE_COUNTRY);

          authnRequest.setDestination(destination);
         authnRequest.setProviderName(sessionRequest.getProviderName());
         authnRequest.setQaa(qaaLevel);
         authnRequest.setPersonalAttributeList(personalList);

         authnRequest.setSPID(providerId);
         if(getServiceMetadataActive() && getServiceRequesterMetadataUrl()!=null && !getServiceRequesterMetadataUrl().isEmpty()) {
            authnRequest.setIssuer(getServiceRequesterMetadataUrl());
         }
         authnRequest.setEidasLoA(eidasLoa);
         authnRequest.setEidasNameidFormat(eidasNameidFormat);
         engine.initRequestedAttributes(personalList);

    	 authnRequest.setAssertionConsumerServiceURL(assertion);
         if(engine.getExtensionProcessor()!=null && engine.getExtensionProcessor().getFormat()==SAMLExtensionFormat.EIDAS10){
        	 authnRequest.setAssertionConsumerServiceURL(null);
             authnRequest.setBinding(EIDASAuthnRequest.BINDING_EMPTY);
         }
         
         authnRequest = engine.generateEIDASAuthnRequest(authnRequest);
         
         session.put(
            EIDASParameters.SAML_IN_RESPONSE_TO_IDP.toString(),
            authnRequest.getSamlId());
         session.put(EIDASParameters.ISSUER_IDP.toString(), authnRequest.getIssuer());
         
      } catch (final EIDASSAMLEngineException e) {
         LOG.info("Errror genereating SAML Token for Authentication Request",e.getMessage());
         LOG.debug("Errror genereating SAML Token for Authentication Request",e);
         throw new InternalErrorEIDASException(
            "0",
            "error genereating SAML Token for Authentication Request",
            e);
      }finally{
          getSamlEngineFactory().releaseEngine(engine);
       }
      
      return authnRequest.getTokenSaml();
   }
   
   /**
    * Getter for specificProps.
    * 
    * @return The specificProps value.
    */
   public IEIDASConfigurationProxy getSpecificProps() {
      return this.specificProps;
   }
   
   /**
    * Setter for specificProps.
    * 
    * @param specificProps The specificProps to set.
    */
   public void setSpecificProps(final IEIDASConfigurationProxy specificProps) {
      this.specificProps = specificProps;
   }
   
   /**
    * Setter for derivedImpls.
    * 
    * @param derivedImpls the derivedImpls to set.
    */
   public void
      setDerivedImpls(final Map<String, IDeriveAttribute> derivedImpls) {
      this.derivedImpls = derivedImpls;
   }
   
   /**
    * Getter for derivedImpls.
    * 
    * @return The derivedImpls value.
    */
   public Map<String, IDeriveAttribute> getDerivedImpls() {
      return derivedImpls;
   }
   
   /**
    * Setter for normaliseImpls.
    * 
    * @param normaliseImpls The normaliseImpls to set.
    */
   public void
      setNormaliseImpls(final Map<String, INormaliseValue> normaliseImpls) {
      this.normaliseImpls = normaliseImpls;
   }
   
   /**
    * Getter for normaliseImpls.
    * 
    * @return The normaliseImpls value.
    */
   public Map<String, INormaliseValue> getNormaliseImpls() {
      return normaliseImpls;
   }
   
   /**
    * Setter for validateImples.
    * 
    * @param validateImples The validateImples to set.
    */
   public void
      setValidateImpls(final Map<String, ICheckAttributeValue> validateImples) {
      this.validateImpls = validateImples;
   }
   
   /**
    * Getter for validateImples.
    * 
    * @return The validateImples value.
    */
   public Map<String, ICheckAttributeValue> getValidateImpls() {
      return validateImpls;
   }

   public String getServiceMetadataUrl() {
      return serviceMetadataUrl;
   }

   public void setServiceMetadataUrl(String serviceMetadataUrl) {
      this.serviceMetadataUrl = serviceMetadataUrl;
   }

   public Boolean getServiceMetadataActive() {
      return serviceMetadataActive;
   }

   public void setServiceMetadataActive(Boolean serviceMetadataActive) {
      this.serviceMetadataActive = serviceMetadataActive;
   }

   public String getServiceRequesterMetadataUrl() {
      return serviceRequesterMetadataUrl;
   }

   public void setServiceRequesterMetadataUrl(String serviceRequesterMetadataUrl) {
      this.serviceRequesterMetadataUrl = serviceRequesterMetadataUrl;
   }
}
