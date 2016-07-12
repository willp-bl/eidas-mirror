package es.stork.signModule.actions;
/**
 * The Class ParseRequestAction.
 * 
 * @author iinigo
 */
import java.io.ByteArrayInputStream;
import java.io.InputStream;

import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;

import org.apache.struts2.interceptor.ServletRequestAware;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import com.opensymphony.xwork2.Action;
import com.opensymphony.xwork2.ActionSupport;

import es.stork.signModule.common.Constants;
import es.stork.signModule.common.DSSNamespaceContext;
import es.stork.signModule.exceptions.SignModuleException;

@SuppressWarnings("serial")
public class ParseRequestAction extends ActionSupport implements ServletRequestAware{
	
	private String textToSign;
	private String requestId;
	private HttpServletRequest request;

	public String execute(){
					
		 DocumentBuilderFactory domFactory = DocumentBuilderFactory.newInstance();
		 domFactory.setNamespaceAware(true); 		 
		 Document doc = null;
		 requestId = null;
		 
		 try {
			 DocumentBuilder builder = domFactory.newDocumentBuilder();
			 String DSSReq =  (String) request.getParameter("XMLRequest");
			 InputStream is = new ByteArrayInputStream(DSSReq.getBytes("UTF-8"));
			 doc = builder.parse(is);
			 is.close();
		 } catch (Exception e) {
				throw new SignModuleException(Constants.REQUESTER_ERROR, requestId);
		 }

		 XPathFactory factory = XPathFactory.newInstance();
		 XPath xpath = factory.newXPath();
		 xpath.setNamespaceContext(new DSSNamespaceContext());
		 
		 try {			 
			 XPathExpression requestIdExpr = xpath.compile("//dss:SignRequest/@RequestID");
			 requestId = (String)requestIdExpr.evaluate(doc, XPathConstants.STRING);

			 XPathExpression textToSignExpr = xpath.compile("//dss:SignRequest/dss:InputDocuments/dss:Document/dss:Base64Data/text()");
		  	 Node node = (Node)textToSignExpr.evaluate(doc, XPathConstants.NODE);
		 	 textToSign = node.getNodeValue();
		} catch (Exception e) {
			throw new SignModuleException(Constants.INSUFICIENT_INFORMATION, requestId);
		}
		 		 				 return Action.SUCCESS;
	}	
	
	public String getTextToSign() {
		return textToSign;
	}

	public void setTextToSign(String textToSign) {
		this.textToSign = textToSign;
	}

	public String getRequestId() {
		return requestId;
	}

	public void setRequestId(String requestId) {
		this.requestId = requestId;
	}

	public void setServletRequest(HttpServletRequest request) {
		this.request = request;		
		
	}	
}
