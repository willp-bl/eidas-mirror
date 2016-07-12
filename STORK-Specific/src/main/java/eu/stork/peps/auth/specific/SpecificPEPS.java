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
package eu.stork.peps.auth.specific;

import java.util.*;

import eu.stork.peps.auth.commons.*;
import eu.stork.peps.auth.commons.exceptions.*;
import eu.stork.peps.auth.engine.core.StorkSAMLEngineFactoryI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.stork.peps.auth.engine.STORKSAMLEngine;
import eu.stork.peps.exceptions.STORKSAMLEngineException;

/**
 * This class is specific and should be modified by each member state if they
 * want to use any different settings.
 * 
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com, hugo.magalhaes@multicert.com
 */
@SuppressWarnings("PMD")
public final class SpecificPEPS implements IAUService, ITranslatorService {
   
   /**
    * Logger object.
    */
   private static final Logger LOG = LoggerFactory.getLogger(SpecificPEPS.class
      .getName());
   
   /**
    * Specific configurations.
    */
   private IPEPSConfigurationProxy specificProps;
   
   private Map<String, IDeriveAttribute> derivedImpls;
   
   private Map<String, INormaliseValue> normaliseImpls;
   
   private Map<String, ICheckAttributeValue> validateImpls;

    private Properties cpepsProperties;
    private StorkSAMLEngineFactoryI samlEngineFactory;
   private String cpepsMetadataUrl;
   private String cpepsRequesterMetadataUrl;
   private Boolean cpepsMetadataActive;

    public StorkSAMLEngineFactoryI getSamlEngineFactory() {
        return samlEngineFactory;
    }

    public void setSamlEngineFactory(StorkSAMLEngineFactoryI samlEngineFactory) {
        this.samlEngineFactory = samlEngineFactory;
    }
    public Properties getCpepsProperties() {
        return cpepsProperties;
    }

    public void setCpepsProperties(Properties pepsProps) {
        this.cpepsProperties = pepsProps;
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
         final IStorkSession session) {

      final String destination =
         (String) parameters.get(PEPSParameters.IDP_URL.toString());
      final String assertion =
         (String) parameters.get(PEPSParameters.CPEPS_CALLBACK.toString());

      return this.generateAuthenticationRequest(
              destination,
              assertion,
              (Integer) parameters.get(PEPSParameters.QAALEVEL.toString()),
              (String) parameters.get(PEPSParameters.EIDAS_SERVICE_LOA.toString()),
              personalList,
              session,
              (String) parameters.get(PEPSParameters.EIDAS_NAMEID_FORMAT.toString()));
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
      final IStorkSession session) {

      final String apId = (String) session.get(PEPSParameters.AP_ID.toString());
      final int apNumber =
         Integer.parseInt(specificProps.getPepsParameterValue(PEPSParameters.AP_NUMBER
                 .toString()));
      
      if (apNumber <= 0) {
         LOG.debug("There are no APs");
         return false;
      }
      
      if (apId != null) {
         final int currApNumber =
            Integer.parseInt(apId.split(PEPSValues.AP.toString())[1]);
         if (currApNumber < apNumber) {
            LOG.debug("Current AP : ap"
               + (currApNumber));
            LOG.debug("Next AP : ap"
               + (currApNumber + 1));
            session.put(PEPSParameters.AP_ID.toString(), PEPSValues.AP
               .toString()
               + (currApNumber + 1));
            session.put(PEPSParameters.AP_URL.toString(), specificProps
               .getPepsParameterValue(PEPSValues.AP.url(currApNumber + 1)));
            LOG.trace("True");
            return true;
         } else {
            LOG.debug("Current AP : ap"
               + (currApNumber));
            LOG.debug("No more APs");
            session.remove(PEPSParameters.AP_ID.toString());
            session.remove(PEPSParameters.AP_URL.toString());
            LOG.trace("False");
            return false;
         }
      } else {
         LOG.debug("Saving AP: ap1");
         session.put(
            PEPSParameters.AP_ID.toString(),
            PEPSValues.AP.toString() + 1);
         session.put(PEPSParameters.AP_URL.toString(), specificProps
            .getPepsParameterValue(PEPSValues.AP.url(1)));
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
         final IStorkSession session,
         final String auProcessID) {

      return true;
   }
   
   /**
    * {@inheritDoc}
    */
   public IPersonalAttributeList
      normaliseAttributeNamesToStork(final IPersonalAttributeList personalList) {

      final IPersonalAttributeList pal =
         new PersonalAttributeList(personalList.size());
      
      final boolean allowUnknowns =
         Boolean.valueOf(specificProps
            .getPepsParameterValue(PEPSParameters.SPECIFIC_ALLOW_UNKNOWNS.toString()));
      
      final int nNames =
         Integer.parseInt(specificProps
            .getPepsParameterValue(PEPSParameters.STORK_ATTRIBUTE_NUMBER.toString()));
      final Map<String, String> attributes = new HashMap<String, String>();
      
      for (int i = 1; i <= nNames; i++) {
         final String attrName =
            specificProps.getPepsParameterValue(PEPSValues.STORK_ATTRIBUTE.index(i));
         final String storkName =
            specificProps.getPepsParameterValue(PEPSValues.STORK_ATTRIBUTE.name(i));
         attributes.put(attrName, storkName);
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
               throw new InvalidParameterPEPSException(
                  PEPSUtil.getConfig(PEPSErrors.INVALID_ATTRIBUTE_LIST
                     .errorCode()),
                  PEPSUtil.getConfig(PEPSErrors.INVALID_ATTRIBUTE_LIST
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
      normaliseAttributeNamesFromStork(final IPersonalAttributeList personalList) throws SecurityPEPSException {

      LOG.trace("On normaliseAttributeNamesToStork method");
      
      final int nNames =
         Integer.parseInt(specificProps
            .getPepsParameterValue(PEPSParameters.STORK_ATTRIBUTE_NUMBER.toString()));
      final Map<String, String> attributes = new HashMap<String, String>();
      
      for (int i = 1; i <= nNames; i++) {
         final String storkName =
            specificProps.getPepsParameterValue(PEPSValues.STORK_ATTRIBUTE.name(i));
         final String attrName =
            specificProps.getPepsParameterValue(PEPSValues.STORK_ATTRIBUTE.index(i));
         if (!attributes.containsKey(storkName)) {
            attributes.put(storkName, attrName);
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
      deriveAttributeFromStork(final IPersonalAttributeList personalList) {

      final int nNames =
         Integer.parseInt(specificProps
            .getPepsParameterValue(PEPSParameters.DERIVE_ATTRIBUTE_NUMBER.toString()));
      
      final Map<String, String> derivations = new HashMap<String, String>();
      for (int i = 1; i <= nNames; i++) {
         final String derivedId =
            specificProps.getPepsParameterValue(PEPSValues.DERIVE_ATTRIBUTE.index(i));
         final String derivedName =
            specificProps.getPepsParameterValue(PEPSValues.DERIVE_ATTRIBUTE.name(i));
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
      deriveAttributeToStork(final IStorkSession session,
         final IPersonalAttributeList modifiedList) {

      final IPersonalAttributeList originalList =
         ((STORKAuthnRequest) session.get(PEPSParameters.AUTH_REQUEST
            .toString())).getPersonalAttributeList();
      
      final int nNames =
         Integer.parseInt(specificProps
            .getPepsParameterValue(PEPSParameters.DERIVE_ATTRIBUTE_NUMBER.toString()));
      
      Map<String, String> derivatedAttrs = new HashMap<String, String>(nNames);
      for (int i = 1; i <= nNames; i++) {
         final String derivedId =
            specificProps.getPepsParameterValue(PEPSValues.DERIVE_ATTRIBUTE.index(i));
         final String derivedName =
            specificProps.getPepsParameterValue(PEPSValues.DERIVE_ATTRIBUTE.name(i));
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
      normaliseAttributeValuesToStork(final IPersonalAttributeList personalList) {

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
                   normaliseValue.normaliseAttributeValueToStork(personalAttribute);
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
          if(!aliasNumbers.isEmpty()) {
              personalAttributeList.keySet().removeAll(aliasNumbers);
          }
       }
      
      return personalList;
   }
   
   /**
    * {@inheritDoc}
    */
   public STORKAuthnResponse
      processAuthenticationResponse(final byte[] samlToken,
         final IStorkSession session) {

      final STORKSAMLEngine engine = getSamlEngineFactory().getEngine(getSamlEngine(), getCpepsProperties());
      STORKAuthnResponse authnResponse;
      try {
          STORKAuthnRequest request=(STORKAuthnRequest) session.get(PEPSParameters.AUTH_REQUEST.toString());
          final String respondTo = request.getCitizenCountryCode();
          engine.setCountryRespondTo(respondTo);
          engine.initRequestedAttributes(request.getPersonalAttributeList());
          authnResponse = engine.validateSTORKAuthnResponse(samlToken, (String) session.get(PEPSParameters.REMOTE_ADDR.toString()), 0);    // Skew time from IDP is set to 0
      } catch (final STORKSAMLEngineException e) {
          String code="0";
          String message="Validation Autentication Response.";
         PEPSErrors err=null;
          if (PEPSErrors.isErrorCode(e.getErrorCode())) {
              err=PEPSErrors.fromCode(e.getErrorCode());
              message=PEPSUtil.getConfig(err.errorMessage());
              code=PEPSUtil.getConfig(err.errorCode());
          }
          if(!session.containsKey(PEPSParameters.ERROR_REDIRECT_URL.toString())) {
             session.put(PEPSParameters.ERROR_REDIRECT_URL.toString(), session.get(PEPSParameters.SP_URL.toString()));
          }
         LOG.info("ERROR : Error validating SAML Autentication Response from IdP", e.getMessage());
         LOG.debug("ERROR : Error validating SAML Autentication Response from IdP", e);
         if(err!=null && !err.isShowToUser()){
            throw new CPEPSException("", code, message, e, PEPSUtil.getConfig(PEPSErrors.IDP_SAML_RESPONSE.errorCode()), PEPSUtil.getConfig(PEPSErrors.IDP_SAML_RESPONSE.errorMessage()));
         }else {
            throw new CPEPSException("", code, message, e);
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

      final STORKSAMLEngine engine = getSamlEngineFactory().getEngine(getSamlEngine(), getCpepsProperties());
      
      STORKAuthnResponse error = new STORKAuthnResponse();
      try {
         // create SAML token
         final STORKAuthnRequest request = new STORKAuthnRequest();
         request.setSamlId(inResponseTo);
         request.setIssuer(issuer);
         request.setAssertionConsumerServiceURL(assertionConsumerServiceURL);
         error.setStatusCode(code);
         error.setSubStatusCode(subcode);
         error.setMessage(message);
         error = engine.generateSTORKAuthnResponseFail(request, error, ipUserAddress, false);
      } catch (final STORKSAMLEngineException e) {
         LOG.info("ERROR : Error generating SAMLToken", e.getMessage());
         LOG.debug("ERROR : Error generating SAMLToken",e);
         throw new InternalErrorPEPSException(
            "0", "Error generating SAMLToken", e);
      }
      getSamlEngineFactory().releaseEngine(engine);
      return error.getTokenSaml();
   }

    private boolean haveExpectedName(final IPersonalAttributeList original, String paName, int arraySize){
        boolean attrNotFound = true;
        for (int i = 1; i <= arraySize; i++) {
            final String derivedId =
                    specificProps.getPepsParameterValue(PEPSValues.DERIVE_ATTRIBUTE.index(i));
            final String derivedName =
                    specificProps.getPepsParameterValue(PEPSValues.DERIVE_ATTRIBUTE.name(i));
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
            .getPepsParameterValue(PEPSParameters.DERIVE_ATTRIBUTE_NUMBER.toString()));

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
   public boolean checkAttributeValues(final STORKAuthnRequest authData) {

      final int nNames =
         Integer.parseInt(specificProps
            .getPepsParameterValue(PEPSParameters.ATTR_VALUE_NUMBER.toString()));
      
      final IPersonalAttributeList pal = authData.getPersonalAttributeList();
      
      for (int i = 1; i <= nNames; i++) {
         final String attrName =
            specificProps.getPepsParameterValue(PEPSValues.ATTRIBUTE.index(i));
         final PersonalAttribute pAttr = pal.get(attrName);
         
         if (pAttr != null && !pAttr.isEmptyValue()) {
            final String value =
               specificProps.getPepsParameterValue(PEPSValues.ATTRIBUTE.value(i));
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
      final IStorkSession session, final String eidasNameidFormat) {

      final STORKSAMLEngine engine = getSamlEngineFactory().getEngine(getSamlEngine(), getCpepsProperties());

      STORKAuthnRequest authnRequest = new STORKAuthnRequest();
      
      final String providerId = PEPSValues.CPEPS.toString();
      
      try {
          final STORKAuthnRequest sessionRequest = (STORKAuthnRequest)session.get(PEPSParameters.AUTH_REQUEST.toString());

          engine.setCountryResponseFrom(sessionRequest.getCitizenCountryCode());

          // generate authentication request
          authnRequest.setSpSector("NOT AVAILABLE");
          authnRequest.setSpInstitution("NOT AVAILABLE");
          authnRequest.setSpApplication("NOT AVAILABLE");

          authnRequest.setSpCountry("NA");

          authnRequest.setDestination(destination);
         authnRequest.setProviderName(providerId);
         authnRequest.setQaa(qaaLevel);
         authnRequest.setPersonalAttributeList(personalList);
         authnRequest.setAssertionConsumerServiceURL(assertion);

         authnRequest.setSPID(providerId);
         if(getCpepsMetadataActive() && getCpepsRequesterMetadataUrl()!=null && !getCpepsRequesterMetadataUrl().isEmpty()) {
            authnRequest.setIssuer(getCpepsRequesterMetadataUrl());
         }
         authnRequest.setEidasLoA(eidasLoa);
         authnRequest.setEidasNameidFormat(eidasNameidFormat);
         engine.initRequestedAttributes(personalList);
         authnRequest = engine.generateSTORKAuthnRequest(authnRequest);
         
         session.put(
            PEPSParameters.SAML_IN_RESPONSE_TO_IDP.toString(),
            authnRequest.getSamlId());
         session.put(PEPSParameters.ISSUER_IDP.toString(), authnRequest.getIssuer());
         
      } catch (final STORKSAMLEngineException e) {
         LOG.info("Errror genereating SAML Token for Authentication Request",e.getMessage());
         LOG.debug("Errror genereating SAML Token for Authentication Request",e);
         throw new InternalErrorPEPSException(
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
   public IPEPSConfigurationProxy getSpecificProps() {
      return this.specificProps;
   }
   
   /**
    * Setter for specificProps.
    * 
    * @param specificProps The specificProps to set.
    */
   public void setSpecificProps(final IPEPSConfigurationProxy specificProps) {
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

   public String getCpepsMetadataUrl() {
      return cpepsMetadataUrl;
   }

   public void setCpepsMetadataUrl(String cpepsMetadataUrl) {
      this.cpepsMetadataUrl = cpepsMetadataUrl;
   }

   public Boolean getCpepsMetadataActive() {
      return cpepsMetadataActive;
   }

   public void setCpepsMetadataActive(Boolean cpepsMetadataActive) {
      this.cpepsMetadataActive = cpepsMetadataActive;
   }

   public String getCpepsRequesterMetadataUrl() {
      return cpepsRequesterMetadataUrl;
   }

   public void setCpepsRequesterMetadataUrl(String cpepsRequesterMetadataUrl) {
      this.cpepsRequesterMetadataUrl = cpepsRequesterMetadataUrl;
   }
}
