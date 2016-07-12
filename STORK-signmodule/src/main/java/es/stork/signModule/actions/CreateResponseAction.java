package es.stork.signModule.actions;

/**
 * The Class CreateResponseAction.
 * 
 * @author iinigo
 */

import java.io.*;
import java.util.Properties;

import org.apache.struts2.interceptor.ServletRequestAware;
import org.apache.struts2.interceptor.ServletResponseAware;
import org.w3c.dom.*;

import com.opensymphony.xwork2.Action;
import com.opensymphony.xwork2.ActionSupport;

import es.stork.signModule.common.Constants;
import es.stork.signModule.exceptions.SignModuleException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.*;

import javax.xml.transform.*;
import javax.xml.transform.dom.*;
import javax.xml.transform.stream.*;

@SuppressWarnings("serial")
public class CreateResponseAction extends ActionSupport implements ServletRequestAware, ServletResponseAware{
	
	private String signedDoc;
	private HttpServletRequest request;	
	private String returnUrl;
	private String requestId;	

	public Properties loadProp() throws Exception{
		
		Properties properties = new Properties();
		InputStream inputStream = ParseRequestAction.class.getResourceAsStream("/" + Constants.SIGN_MODULE_PROPERTIES);
		properties.load(inputStream);
		inputStream.close();		
		return properties;
		
	}

	public String execute() {
		try{	
			returnUrl = (String) loadProp().get(Constants.PEPS_RETURN_URL);
			
            DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
            dbfac.setNamespaceAware(true);
            DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
            Document doc = docBuilder.newDocument();

            //create the root element and add it to the document
            Element root = doc.createElement("dss:SignResponse");
            root.setAttribute("xmlns:dss", "urn:oasis:names:tc:dss:1.0:core:schema");
            root.setAttribute("RequestID", requestId);
            doc.appendChild(root);
           
            	//Create Result Element
            	Element result = doc.createElement("dss:Result");
            	root.appendChild(result);
            		
            		//Create ResultMajor Element
            		Element resultMajor = doc.createElement("dss:ResultMajor");
            		result.appendChild(resultMajor);
           			Text success = doc.createTextNode("urn:oasis:names:tc:dss:1.0:resultmajor:Success");
           			resultMajor.appendChild(success);
            
            	//Create SignatureObject element
            	Element  signatureObject= doc.createElement("dss:SignatureObject");
            	root.appendChild(signatureObject);
            		
            		//Create Base64Signature Element
            		Element  base64= doc.createElement("dss:Base64Signature");
            		base64.setAttribute("Type", "urn:ietf:rfc:3275");
            		signatureObject.appendChild(base64);
            		Text signedText = doc.createTextNode(request.getParameter("XMLResponse").replace("\r\n",""));
            		base64.appendChild(signedText);

            //set up a transformer
            TransformerFactory transfac = TransformerFactory.newInstance();
            Transformer trans = transfac.newTransformer();
            trans.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            trans.setOutputProperty(OutputKeys.INDENT, "yes");

            //create string from xml tree
            StringWriter sw = new StringWriter();
            StreamResult resultT = new StreamResult(sw);
            DOMSource source = new DOMSource(doc);
            trans.transform(source, resultT);
            String xmlString = sw.toString();            
            
            this.signedDoc = xmlString;
        
		} catch (Exception e) {
			throw new SignModuleException(Constants.RESPONDER_ERROR, requestId);
		}
        
        return Action.SUCCESS;
    }
	
	public void setServletRequest(HttpServletRequest request) {
		this.request = request;
	}

	public void setServletResponse(HttpServletResponse response) {
	}
	
	public String getSignedDoc() {
		return signedDoc;
	}

	public void setSignedDoc(String signedDoc) {
		this.signedDoc = signedDoc;
	}
	
	public String getReturnUrl() {
		return returnUrl;
	}

	public void setReturnUrl(String returnUrl) {
		this.returnUrl = returnUrl;
	}
	
	public String getRequestId() {
		return requestId;
	}

	public void setRequestId(String requestId) {
		this.requestId = requestId;
	}
}