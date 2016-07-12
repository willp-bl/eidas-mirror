package es.stork.signModule.exceptions;

/**
 * The Class SignModuleException.
 * 
 * @author iinigo
 */

import java.io.InputStream;
import java.io.StringWriter;
import java.util.Properties;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

import es.stork.signModule.actions.ParseRequestAction;
import es.stork.signModule.common.Constants;

@SuppressWarnings("serial")
public class SignModuleException extends RuntimeException {
	
	private String resultMajorText;
	private String requestId;
		
	public Properties loadProp() throws Exception{	
		Properties properties = new Properties();
		InputStream inputStream = ParseRequestAction.class.getResourceAsStream("/" + Constants.SIGN_MODULE_PROPERTIES);
		properties.load(inputStream);
		inputStream.close();		
		return properties;
	}
		
	public SignModuleException(String result, String requestId) {
		this.resultMajorText = result;
		this.requestId = requestId;
	}
	
	public String getReturnUrl() throws Exception{
		String returnUrl = (String) loadProp().get(Constants.PEPS_RETURN_URL);
		return returnUrl;
	}
	
	public String getSignErrorResponse() throws Exception{
		
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
        			Text success = doc.createTextNode(this.resultMajorText);
        			resultMajor.appendChild(success);         			

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
         return sw.toString();                  
	}
}