package eu.stork.peps.auth.engine.core.validator;

import java.util.regex.Pattern;

import eu.stork.peps.auth.engine.core.stork.CitizenCountryCode;
import org.opensaml.xml.validation.ValidationException;
import org.opensaml.xml.validation.Validator;


/**
 * Created with IntelliJ IDEA.
 * User: s228576
 * Date: 23/02/14
 * Time: 15:45
 * To change this template use File | Settings | File Templates.
 */
public class StorkCitizenCountryCodeValidator implements
        Validator<CitizenCountryCode> {

    public static final String REGEX_PATTERN = "^[A-Za-z]{2}$";

    public StorkCitizenCountryCodeValidator() {

    }

    public void validate(CitizenCountryCode ccc) throws ValidationException {

        if (ccc == null) {

            throw new ValidationException("CitizenCountryCode is required.");
        }
        if (ccc.getCitizenCountryCode() == null) {
            throw new ValidationException("CitizenCountryCode has no value");
        }


        if (!Pattern.matches(REGEX_PATTERN, ccc.getCitizenCountryCode())) {
            throw new ValidationException("CitizenCountryCode not valid: " + ccc.getCitizenCountryCode());
        }


    }

}

