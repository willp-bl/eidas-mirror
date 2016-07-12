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

package eu.eidas.auth.engine.core.eidas.impl;

import eu.eidas.auth.engine.core.SAMLCore;
import eu.eidas.auth.engine.core.eidas.GenericEidasAttributeType;

import org.opensaml.common.impl.AbstractSAMLObjectMarshaller;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Attr;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;

import java.util.Map;

/**
 * The Class GenericEidasAttributeTypeMarshaller.
 * 
 */
public class GenericEidasAttributeTypeMarshaller extends AbstractSAMLObjectMarshaller {

    private static final String ATTR_SEPARATOR=":";

    protected final void marshallAttributes(final XMLObject samlElement,
                                            final Element domElement) throws MarshallingException {
        final GenericEidasAttributeType geat = (GenericEidasAttributeType) samlElement;

        for (Map.Entry<String, String> entry: geat.getAttributeMap().entrySet()) {
            //key has the format prefix:AttrName
            if(entry.getKey()==null || entry.getKey().indexOf(':')<=0){
                continue;
            }
            String attrPrefix=entry.getKey().substring(0, entry.getKey().indexOf(ATTR_SEPARATOR));
            String attrName=entry.getKey().substring(entry.getKey().indexOf(ATTR_SEPARATOR)+1);
            Attr attr = XMLHelper.constructAttribute(domElement.getOwnerDocument(),
                    new QName(SAMLCore.EIDAS10_RESPONSESAML_NS.getValue(), attrName, attrPrefix ));
            attr.setValue(entry.getValue());
            domElement.setAttributeNodeNS(attr);
        }
    }

    /**
     * Marshall element content.
     *
     * @param samlObject the SAML object
     * @param domElement the DOM element
     * @throws MarshallingException the marshalling exception
     */
    protected final void marshallElementContent(final XMLObject samlObject,
                                                final Element domElement) throws MarshallingException {
        final GenericEidasAttributeType geat = (GenericEidasAttributeType) samlObject;
        Map<String, String> attributes=geat.getAttributeMap();
        for(Map.Entry<String, String> entry:attributes.entrySet()){
            domElement.setAttribute(entry.getKey(), entry.getValue());
        }
        XMLHelper.appendTextContent(domElement, geat.getValue());
    }
}