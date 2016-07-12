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
package eu.eidas.auth.engine.core.validator.eidas;




import eu.eidas.auth.engine.core.eidas.RequestedAttribute;

import org.opensaml.saml2.metadata.validator.RequestedAttributeSchemaValidator;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.LoggerFactory;


public class EidasRequestedAttributeValidator extends
        RequestedAttributeSchemaValidator {

    /** The Constant LOG. */
    private static final org.slf4j.Logger LOG = LoggerFactory.getLogger(EidasRequestedAttributeValidator.class.getName());

    public EidasRequestedAttributeValidator() {

        super();
    }

    public void validate(RequestedAttribute attr) throws ValidationException {
        LOG.info("Validating the attribute "+attr.getName());

        //Attributes requested that are not supported by an eIDAS-Service MUST be ignored by the eIDAS-Service.
        /*if (!eu.eidas.auth.engine.core.validator.eidas.EIDASAttributes.ATTRIBUTES_TO_ATTRIBUTETYPE.containsKey(attr.getName()) && !attr.isRequired().isEmpty() && "true".equals(attr.isRequired())) {
            throw new ValidationException("Mandatory RequestedAttribute \"" + attr.getName() + "\" is not valid");
        }*/

        if (attr.getName() == null) {

            throw new ValidationException("Name is required.");
        }

        if (attr.getNameFormat() == null) {

            throw new ValidationException("NameFormat is required.");
        }

        /*if (!eu.eidas.auth.engine.core.validator.eidas.EIDASAttributes.ATTRIBUTES_TO_ATTRIBUTETYPE.containsKey(attr.getName()) && !attr.isRequired().isEmpty() && "true".equals(attr.isRequired())) {
            throw new ValidationException("Mandatory RequestedAttribute \"" + attr.getName() + "\" is not valid");
        }*/

    }

}
