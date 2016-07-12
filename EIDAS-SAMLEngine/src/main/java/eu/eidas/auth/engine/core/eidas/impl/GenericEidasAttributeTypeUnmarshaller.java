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

import eu.eidas.auth.engine.core.eidas.GenericEidasAttributeType;

import org.opensaml.common.impl.AbstractSAMLObjectUnmarshaller;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.UnmarshallingException;
import org.w3c.dom.Attr;


/**
 * The Class GenericEidasAttributeTypeUnmarshaller.
 */
public class GenericEidasAttributeTypeUnmarshaller extends AbstractSAMLObjectUnmarshaller {


    protected final void processElementContent(final XMLObject samlObject,
                                               final String elementContent) {
        final GenericEidasAttributeType genericEidasAttributeType = (GenericEidasAttributeType) samlObject;
        genericEidasAttributeType.setValue(elementContent);
    }
    protected void processAttribute(XMLObject samlObject, Attr attribute) throws UnmarshallingException {
        final GenericEidasAttributeType genericEidasAttributeType = (GenericEidasAttributeType) samlObject;
        genericEidasAttributeType.getAttributeMap().put(attribute.getName(), attribute.getValue());
    }

}