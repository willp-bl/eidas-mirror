package eu.stork.sp;

import java.util.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import eu.stork.peps.auth.commons.*;
import org.apache.struts2.interceptor.ServletRequestAware;
import org.apache.struts2.interceptor.ServletResponseAware;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.opensymphony.xwork2.Action;
import com.opensymphony.xwork2.ActionSupport;

import eu.stork.peps.auth.engine.STORKSAMLEngine;
import eu.stork.peps.exceptions.STORKSAMLEngineException;

/**
 * 
 * @author iinigo
 * This Action Generates a SAML Request with the data given by the user, then sends it to the selected peps
 *
 */

public class IndexAction extends ActionSupport implements ServletRequestAware, ServletResponseAware {

    private static final long serialVersionUID = 3660074009157921579L;
	
	static final Logger LOGGER = LoggerFactory.getLogger(IndexAction.class.getName());
    public static final String ACTION_REDIRECT = "redirect";
    public static final String ACTION_POPULATE = "populate";
    public static final String ATTRIBUTE_SIGNED_DOC = "signedDoc";
    private static final String SPTYPE_PARAM="spType";

    private HttpServletRequest request;
	private String SAMLRequest;
	private String samlRequestXML;	

	private static Properties configs; 
	private static ArrayList<Country> countries;
	private static ArrayList<PersonalAttribute> storkAttributeList;
	private static ArrayList<PersonalAttribute> eidasAttributeList;

	private static String spId;
	private static String providerName;
	private static String spSector;
	//private static String spInstitution;
	private static String spApplication;
	private static String spCountry;
	
	/*Requested parameters*/
	private String pepsUrl; 
	private String pepsUrl2;	
	private String qaa;
	private String citizen;
	private String returnUrl;
	private String eidasloa;
	private String eidasloaCompareType;
	private String eidasNameIdentifier;
	private String eidasSPType;

	private static void loadGlobalConfig(){
		configs = SPUtil.loadSPConfigs();
		spId = configs.getProperty(Constants.PROVIDER_NAME);
		providerName = configs.getProperty(Constants.PROVIDER_NAME);
		spSector = configs.getProperty(Constants.SP_SECTOR);
		//spInstitution = configs.getProperty(Constants.PROVIDER_NAME);
		spApplication = configs.getProperty(Constants.SP_APLICATION);
		spCountry = configs.getProperty(Constants.SP_COUNTRY);
		countries = new ArrayList<Country> ();
        storkAttributeList = new ArrayList<PersonalAttribute>();
        eidasAttributeList = new ArrayList<PersonalAttribute>();

    }
    /**
 	 * Fill the data in the JSP that is shown to the user in order to fill the requested data to generate a saml request
     * @return ACTION_REDIRECT
     */
	public String populate() {		
				
		IndexAction.loadGlobalConfig();

		returnUrl = configs.getProperty(Constants.SP_RETURN);
		qaa = configs.getProperty(Constants.SP_QAALEVEL);		

		int numCountries = Integer.parseInt(configs.getProperty(Constants.COUNTRY_NUMBER));
		for(int i=1;i<=numCountries;i++){
			Country country = new Country(i,configs.getProperty("country" + Integer.toString(i) + ".name"), configs.getProperty("country" + Integer.toString(i) + ".url"), configs.getProperty("country" + Integer.toString(i) + ".countrySelector"));
			countries.add(country);
            LOGGER.info(country.toString());
		}
		
		int nAttr = Integer.parseInt( configs.getProperty(Constants.ATTRIBUTE_NUMBER));
		

		for(int i=1; i<=nAttr; i++){
			PersonalAttribute pa = new PersonalAttribute();
			pa.setName(configs.getProperty("attribute"+ i +".name"));
			
			String value = configs.getProperty("attribute"+ i + ".value");
			if(value != null){
				ArrayList<String> aux= new ArrayList<String>();
				aux.add(value);
				pa.setValue(aux);
			}
			
			storkAttributeList.add(pa);
		}

		if(configs.getProperty(Constants.EIDAS_ATTRIBUTE_NUMBER)!=null) {
			nAttr = Integer.parseInt(configs.getProperty(Constants.EIDAS_ATTRIBUTE_NUMBER));
			for (int i = 1; i <= nAttr; i++) {
				PersonalAttribute pa = new PersonalAttribute();
				pa.setName(configs.getProperty("eidas.attribute" + i + ".name"));

				String value = configs.getProperty("eidas.attribute" + i + ".value");
				if (value != null) {
					ArrayList<String> aux = new ArrayList<String>();
					aux.add(value);
					pa.setValue(aux);
				}

				eidasAttributeList.add(pa);
			}
		}

		return ACTION_POPULATE;
	}
	
	
	
/**
 * Set the request to send to the country selector
 * @return ACTION_REDIRECT
 */
public String redirect(){		
		
	StringBuilder strBld = new StringBuilder();
    IPersonalAttributeList pAttList = new PersonalAttributeList();
	
	//Iterate through the request parameters looking for SAML Engine attributes
    PersonalAttribute attrSigned = null;
	for (Enumeration enu = request.getParameterNames(); enu.hasMoreElements();)  {
		String parameterName = (String) enu.nextElement();
		if(configs.containsValue(parameterName)){
			//Iterate through the request parameters looking for SAML Engine attribute types*/
			for (Enumeration en = request.getParameterNames(); en.hasMoreElements();)  {
				String parameterType = (String) en.nextElement();
				if(parameterType.equals(parameterName + "Type")){
					if(!"none".equals(request.getParameter(parameterType))){
						//Construct attributes string in order to send it to the country selector in the PEPS
                        PersonalAttribute attr = new PersonalAttribute();
                        attr.setName(parameterName);
                        Boolean attrType = Boolean.valueOf(request.getParameter(parameterType));
                        attr.setIsRequired(attrType.booleanValue());
 						
						//Iterate through the request parameters looking for SAML Engine attribute values
						for (Enumeration e = request.getParameterNames(); e.hasMoreElements();)  {
							String parameterValue = (String) e.nextElement();
							if(parameterValue.equals(parameterName + "Value")){
								List<String> value = new ArrayList<String>();
								value.add(request.getParameter(parameterValue));  
								attr.setValue(value);
							}				
						}
                        // Correction of the signedDoc issue causing the rest of the string to be ignored (1/2)
                        // This attribute will be added as latest for causing xml string to be closed
                        if (ATTRIBUTE_SIGNED_DOC.equals(attr.getName())){
                            attrSigned = attr;
                        } else {
                            strBld.append(attr.toString());
                        }
                        pAttList.add(attr);

					}
				}				
			}
		}
	}
    // Correction of the signedDoc issue causing the rest of the string to be ignored (2/2)
	if (attrSigned != null) {
        strBld.append(attrSigned.toString());
    }
	request.setAttribute(PEPSParameters.ATTRIBUTE_LIST.toString(), strBld.toString());
	request.setAttribute(PEPSParameters.PROVIDER_NAME_VALUE.toString(), providerName);
	request.setAttribute(PEPSParameters.SP_URL.toString(), returnUrl);
	request.setAttribute(PEPSParameters.SP_QAALEVEL.toString(), qaa);
	request.setAttribute("pepsCountryForm", pepsUrl2);
	
	//new parameters
	request.setAttribute(PEPSParameters.SPSECTOR.toString(), spSector);
//	request.setAttribute("spInstitution", spInstitution);
	request.setAttribute(PEPSParameters.SPAPPLICATION.toString(), spApplication);
	request.setAttribute(PEPSParameters.SPCOUNTRY.toString(), spCountry);
	
	//V-IDP parameters
	request.setAttribute(PEPSParameters.SP_ID.toString(), spId);

	String metadataUrl=configs.getProperty(Constants.SP_METADATA_URL);
	if(metadataUrl!=null && !metadataUrl.isEmpty() && SPUtil.isMetadataEnabled()) {
		request.setAttribute(PEPSParameters.SP_METADATA_URL.toString(), metadataUrl);
	}


	return ACTION_REDIRECT;
	
	}
	

	private static final String MAPPING_ATTR_PREFIX="mapping.attribute.";
	/**
	 * Generates de Saml Request with the data given by the user
     * @return Action.SUCCESS
	 */
	public String execute(){
						
		IPersonalAttributeList pAttList = new PersonalAttributeList();
        boolean eIdasRequest=false;
		//Iterate through the request parameters looking for SAML Engine attributes
		for (Enumeration enu = request.getParameterNames(); enu.hasMoreElements();)  {
			String parameterName = (String) enu.nextElement();
            if(SPTYPE_PARAM.equalsIgnoreCase(parameterName)){
                eIdasRequest=true;
            }
			if(configs.containsValue(parameterName)){
				//Iterate through the request parameters looking for SAML Engine attribute types
				for (Enumeration en = request.getParameterNames(); en.hasMoreElements();)  {
					//Create a personal attribute with the attribute and its type
					String parameterType = (String) en.nextElement();
					if(parameterType.equals(parameterName + "Type")){
						if(!"none".equals(request.getParameter(parameterType))){
							PersonalAttribute att = new PersonalAttribute();
							if(configs.containsKey(MAPPING_ATTR_PREFIX+parameterName)){
								att.setName((String)configs.get(MAPPING_ATTR_PREFIX+parameterName));
							}else {
								att.setName(request.getParameter(parameterName));
							}
							if("true".equals(request.getParameter(parameterType)))
								att.setIsRequired(true);
							else
								att.setIsRequired(false);
							//Iterate through the request parameters looking for SAML Engine attribute types
							for (Enumeration e = request.getParameterNames(); e.hasMoreElements();)  {
								//Create a personal attribute with the attribute and its type
								String parameterValue = (String) e.nextElement();
								if(parameterValue.equals(parameterName + "Value")){
									ArrayList<String> aux= new ArrayList<String>();
									aux.add(request.getParameter(parameterValue));
									att.setValue(aux);
								}
							}
							pAttList.add(att);							
						}
					}
				}
			}
		}	
		byte[] token = null;
		
		STORKAuthnRequest authnRequest = new STORKAuthnRequest();
		
		authnRequest.setDestination(pepsUrl);
		authnRequest.setProviderName(providerName);
		if(qaa!=null) {
			authnRequest.setQaa(Integer.parseInt(qaa));
		}
		authnRequest.setPersonalAttributeList(pAttList);
		authnRequest.setAssertionConsumerServiceURL(returnUrl);
        if(eIdasRequest) {
            if(EidasLoaLevels.getLevel(eidasloa)==null) {
                authnRequest.setEidasLoA(EidasLoaLevels.LOW.stringValue());
            }else {
                authnRequest.setEidasLoA(eidasloa);
            }
            authnRequest.setSPType(eidasSPType);
			authnRequest.setEidasLoACompareType(EidasLoaCompareType.getCompareType(eidasloaCompareType).stringValue());
			authnRequest.setEidasNameidFormat(eidasNameIdentifier);
        }
		String metadataUrl=configs.getProperty(Constants.SP_METADATA_URL);
		if(metadataUrl!=null && !metadataUrl.isEmpty() && SPUtil.isMetadataEnabled()) {
			authnRequest.setIssuer(metadataUrl);
		}
		
		//new parameters
		authnRequest.setSpSector(spSector);
//		authnRequest.setSpInstitution(spInstitution);
		authnRequest.setSpApplication(spApplication);
		authnRequest.setSpCountry(request.getParameter("speps_ms_input"));
		
		//V-IDP parameters
		authnRequest.setCitizenCountryCode(citizen);
		authnRequest.setSPID(spId);
		
		try{
			STORKSAMLEngine engine = SPUtil.createSAMLEngine(Constants.SP_CONF);
            engine.initRequestedAttributes(pAttList);
			authnRequest = engine.generateSTORKAuthnRequest(authnRequest);
		}catch(STORKSAMLEngineException e){
			LOGGER.error(e.getMessage());
			throw new ApplicationSpecificServiceException("Could not generate token for Saml Request", e.getErrorMessage());
		}	
				
		token = authnRequest.getTokenSaml();
		
		SAMLRequest = PEPSUtil.encodeSAMLToken(token);
		samlRequestXML = new String(token);
		
		return Action.SUCCESS;
	}


	public ArrayList<PersonalAttribute> getStorkAttributeList() {
		return storkAttributeList;
	}
	public ArrayList<PersonalAttribute> getEidasAttributeList() {
		return eidasAttributeList;
	}

	public void setSAMLRequest(String samlToken) {
		this.SAMLRequest = samlToken;
	}

	public String getSAMLRequest() {
		return SAMLRequest;
	}	

	public String getQaa() {
		return qaa;
	}

	public void setQaa(String qaa) {
		this.qaa = qaa;
	}	
	
	public String getSpId() {
		return spId;
	}

	public String getProviderName() {
		return providerName;
	}

	public String getCitizen() {
		return citizen;
	}

	public void setCitizen(String citizen) {
		this.citizen = citizen;
	}

	public void setCitizenEidas(String citizen) {
		setCitizen(citizen);
	}

	public String getSamlRequestXML() {
		return samlRequestXML;
	}

	public void setSamlRequestXML(String samlRequestXML) {
		this.samlRequestXML = samlRequestXML;
	}
	
	public String getReturnUrl() {
		return returnUrl;
	}

	public void setReturnUrl(String returnUrl) {
		this.returnUrl = returnUrl;
	}	
	
	public String getPepsUrl() {
		return pepsUrl;
	}

	public void setPepsUrl(String pepsUrl) {
		this.pepsUrl = pepsUrl;
	}
	
	public ArrayList<Country> getCountries() {
		return countries;
	}


	public void setServletRequest(HttpServletRequest request) {
		this.request = request;
	}

	public void setServletResponse(HttpServletResponse response) {
	}
	
	public String getPepsUrl2() {
		return pepsUrl2;
	}

	public void setPepsUrl2(String pepsUrl2) {
		this.pepsUrl2 = pepsUrl2;
	}

    public String getEidasloa() {
        return eidasloa;
    }

    public void setEidasloa(String eidasloa) {
        this.eidasloa = eidasloa;
    }

	public String getEidasloaCompareType() {
		return eidasloaCompareType;
	}

	public void setEidasloaCompareType(String eidasloaCompareType) {
		this.eidasloaCompareType = eidasloaCompareType;
	}

	public String getEidasNameIdentifier() {
		return eidasNameIdentifier;
	}

	public void setEidasNameIdentifier(String eidasNameIdentifier) {
		this.eidasNameIdentifier = eidasNameIdentifier;
	}

	public String getEidasSPType() {
		return eidasSPType;
	}

	public void setEidasSPType(String eidasSPType) {
		this.eidasSPType = eidasSPType;
	}
}
