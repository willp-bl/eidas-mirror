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
package eu.eidas.auth.engine.core.eidas;

import eu.eidas.auth.engine.core.eidas.impl.*;
import eu.eidas.auth.engine.core.validator.eidas.EIDASAttributes;

import org.opensaml.Configuration;

/**
 * register the configuration for eIDAS format
 * TODO: add unregister method
 */
public class EidasExtensionConfiguration {
    public void configureExtension(){

        Configuration.registerObjectProvider(
                RequestedAttribute.DEF_ELEMENT_NAME,
                new RequestedAttributeBuilder(),
                new RequestedAttributeMarshaller(),
                new RequestedAttributeUnmarshaller());

        Configuration.registerObjectProvider(
                RequestedAttributes.DEF_ELEMENT_NAME,
                new RequestedAttributesBuilder(),
                new RequestedAttributesMarshaller(),
                new RequestedAttributesUnmarshaller());

        Configuration.registerObjectProvider(
                SigningMethod.DEF_ELEMENT_NAME, new SigningMethodBuilder(),
                new SigningMethodMarshaller(), new SigningMethodUnmarshaller());

        Configuration.registerObjectProvider(
                DigestMethod.DEF_ELEMENT_NAME, new DigestMethodBuilder(),
                new DigestMethodMarshaller(), new DigestMethodUnmarshaller());



        Configuration.registerObjectProvider(SPType.DEF_ELEMENT_NAME,
                new SPTypeBuilder(), new SPTypeMarshaller(),
                new SPTypeUnmarshaller());

        Configuration.registerObjectProvider(SPCountry.DEF_ELEMENT_NAME,
                new SPCountryBuilder(), new SPCountryMarshaller(),
                new SPCountryUnmarshaller());
        GenericEidasAttributeTypeBuilder genericBuilder = new GenericEidasAttributeTypeBuilder();
        for(String attrName: EIDASAttributes.ATTRIBUTES_TO_TYPESNAMES.values()){
            Configuration.registerObjectProvider(genericBuilder.buildObject().getDefElementName(attrName),
                    genericBuilder, new GenericEidasAttributeTypeMarshaller(),
                    new GenericEidasAttributeTypeUnmarshaller());

        }

    }
}
