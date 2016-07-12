package eu.stork.peps.auth.engine.core.validator;

import eu.stork.peps.auth.engine.core.stork.RequestedAttribute;
import eu.stork.peps.auth.engine.core.stork.RequestedAttributes;

import org.opensaml.xml.validation.ValidationException;
import org.opensaml.xml.validation.Validator;

import java.util.List;


/**
 * Created with IntelliJ IDEA.
 * User: s228576
 * Date: 4/03/14
 * Time: 10:51
 * To change this template use File | Settings | File Templates.
 */


public class StorkRequestedAttributesValidator implements
        Validator<RequestedAttributes> {

    public StorkRequestedAttributesValidator() {

    }

    public void validate(RequestedAttributes attrs) throws ValidationException {
        StorkRequestedAttributeValidator valRequestedAttribute = new StorkRequestedAttributeValidator();

        List<RequestedAttribute> requestedAttributeList = attrs.getAttributes();

        for (RequestedAttribute storkAttribute : requestedAttributeList) {
            valRequestedAttribute.validate(storkAttribute);
        }
    }
}
