package es.stork.signModule.common;

/**
 * The Class DSSNamespaceContext.
 * 
 * @author iinigo
 */

import java.util.Iterator;

import javax.xml.XMLConstants;
import javax.xml.namespace.NamespaceContext;


public class DSSNamespaceContext implements NamespaceContext {

    public String getNamespaceURI(String prefix) {
        if (prefix == null) 
        	throw new NullPointerException("Null prefix");
        else if ("dss".equals(prefix)) 
        	return "urn:oasis:names:tc:dss:1.0:core:schema";
        else if ("xml".equals(prefix)) 
        	return XMLConstants.XML_NS_URI;
        return XMLConstants.NULL_NS_URI;
    }

    // This method isn't necessary for XPath processing.
    public String getPrefix(String uri) {
        throw new UnsupportedOperationException();
    }

    // This method isn't necessary for XPath processing either.
	public Iterator<Object> getPrefixes(String uri) {
        throw new UnsupportedOperationException();
    }
}
