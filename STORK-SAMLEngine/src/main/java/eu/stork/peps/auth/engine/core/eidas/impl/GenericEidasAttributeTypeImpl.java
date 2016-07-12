/* 
 * Licensed under the EUPL, Version 1.1 or – as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence");
 * You may not use this work except in compliance with the Licence. You may
 * obtain a copy of the Licence at:
 * 
 * http://www.osor.eu/eupl/european-union-public-licence-eupl-v.1.1
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * Licence for the specific language governing permissions and limitations under
 * the Licence.
 */

package eu.stork.peps.auth.engine.core.eidas.impl;

import eu.stork.peps.auth.engine.core.eidas.GenericEidasAttributeType;
import eu.stork.peps.auth.engine.core.validator.eidas.EIDASAttributes;
import org.opensaml.common.impl.AbstractSAMLObject;
import org.opensaml.xml.XMLObject;

import javax.xml.namespace.QName;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


/**
 * The Class GenericEidasAttributeTypeImpl.
 */
public class GenericEidasAttributeTypeImpl extends AbstractSAMLObject implements GenericEidasAttributeType {

    /**
     * Instantiates a new GenericEidasAttributeType implementation.
     *
     * @param namespaceURI the namespace URI
     * @param elementLocalName the element local name
     * @param namespacePrefix the namespace prefix
     */
    protected GenericEidasAttributeTypeImpl(final String namespaceURI,
                                            final String elementLocalName, final String namespacePrefix) {
	super(namespaceURI, elementLocalName, namespacePrefix);
    }

    /**
     * Gets the ordered children.
     * 
     * @return the ordered children
     */
    public final List<XMLObject> getOrderedChildren() {
	    return new ArrayList<XMLObject>();
    }

    @Override
    public int hashCode() {// NOSONAR
        throw new UnsupportedOperationException("hashCode method not implemented");
    }

    @Override
    public String getDefLocalName(String attrName) {
        return EIDASAttributes.ATTRIBUTES_SET_TYPES.containsKey(attrName)? (String)EIDASAttributes.ATTRIBUTES_SET_TYPES.get(attrName):(attrName);
    }

    @Override
    public QName getDefElementName(String attrName) {
        return new QName(TYPE_SUPPORT_NS, getDefLocalName(attrName),TYPE_SUPPORT_PREFIX);
    }

    @Override
    public String getTypeLocalName(String attrName) {
        return getDefLocalName(attrName);
    }

    @Override
    public QName getTypeName(String attrName) {
        return new QName(TYPE_SUPPORT_NS, getTypeLocalName(attrName),TYPE_SUPPORT_PREFIX);
    }

    String value;
    @Override
    public String getValue() {
        return value;
    }

    @Override
    public void setValue(String value) {
        this.value=value;
    }

    Map<String, String> attributes=new HashMap<String, String>();
    @Override
    public Map<String, String> getAttributeMap(){
        return attributes;
    }
}
