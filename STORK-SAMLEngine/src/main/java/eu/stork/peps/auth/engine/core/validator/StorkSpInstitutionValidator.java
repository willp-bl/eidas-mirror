package eu.stork.peps.auth.engine.core.validator;

/**
 * Created with IntelliJ IDEA.
 * User: s228576
 * Date: 23/02/14
 * Time: 17:35
 * To change this template use File | Settings | File Templates.
 */

import eu.stork.peps.auth.engine.core.stork.SPInstitution;
import org.opensaml.xml.validation.ValidationException;
import org.opensaml.xml.validation.Validator;


public class StorkSpInstitutionValidator implements
        Validator<SPInstitution> {

    public static final int MIN_SIZE = 1;
    public static final int MAX_SIZE = 50;

    public StorkSpInstitutionValidator() {

    }

    public void validate(SPInstitution spInstitution) throws ValidationException {

        if (spInstitution != null) {

            if (spInstitution.getSPInstitution() == null) {
                throw new ValidationException("spInstitution has no value");
            }


            if (spInstitution.getSPInstitution().length() < MIN_SIZE || spInstitution.getSPInstitution().length() > MAX_SIZE) {
                throw new ValidationException("spInstitution has wrong size: " + spInstitution.getSPInstitution().length());
            }
        }
    }

}

