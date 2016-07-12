package eu.stork.sp;

import com.opensymphony.xwork2.ActionSupport;
import eu.stork.peps.auth.commons.STORKAuthnRequest;
import eu.stork.peps.auth.engine.STORKSAMLEngine;
import eu.stork.peps.exceptions.STORKSAMLEngineException;
import org.apache.struts2.interceptor.ServletRequestAware;
import org.apache.struts2.interceptor.ServletResponseAware;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.InputStream;

/**
 * 
 * This Action resign the current saml request
 *
 */

public class ResignAction extends ActionSupport implements ServletRequestAware, ServletResponseAware {

	static final Logger logger = LoggerFactory.getLogger(ResignAction.class.getName());
    private static final long serialVersionUID = 8366221022770773467L;
    HttpServletRequest request;

    private String samlRequestXML;
    private String samlRequestBinding;

    private transient InputStream dataStream;

    public String resignAsValidRequest(){
        byte []result;
        try {
            STORKSAMLEngine engine = SPUtil.createSAMLEngine(Constants.SP_CONF);
            STORKAuthnRequest authnRequest = new STORKAuthnRequest();
            authnRequest.setTokenSaml(samlRequestXML.getBytes());
            authnRequest.setBinding(samlRequestBinding);
            authnRequest = engine.resignSTORKAuthnRequest(authnRequest, true);
            result=authnRequest.getTokenSaml();
        }catch(STORKSAMLEngineException ssee){
            logger.info("Error during resigning with validation", ssee);
            result=samlRequestXML.getBytes();
        }
        dataStream = new ByteArrayInputStream(result);
        return SUCCESS;
    }
    public String reSign(){

        byte[] reSigned = new byte[]{};

        try {
            STORKSAMLEngine engine = SPUtil.createSAMLEngine(Constants.SP_CONF);
            reSigned = engine.resignSTORKTokenSAML(samlRequestXML.getBytes());
        }catch(STORKSAMLEngineException ssee){
            logger.error("Error during resigning ", ssee);
        }

        dataStream = new ByteArrayInputStream(reSigned);
        return SUCCESS;

    }
    public InputStream getInputStream(){return dataStream;}
    public void setInputStream(InputStream inputStream){dataStream=inputStream;}


    public String getSamlRequestXML() {
        return samlRequestXML;
    }

    public void setSamlRequestXML(String samlRequestXML) {
        this.samlRequestXML = samlRequestXML;
    }
    public String getSamlRequestBinding() {
        return samlRequestBinding;
    }

    public void setSamlRequestBinding(String binding) {
        this.samlRequestBinding = binding;
    }


    public void setServletRequest(HttpServletRequest request) {
		this.request = request;
	}

	public void setServletResponse(HttpServletResponse response) {
	}
	
}
