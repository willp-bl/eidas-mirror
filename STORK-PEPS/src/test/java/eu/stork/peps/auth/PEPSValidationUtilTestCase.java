/*
 * Copyright (c) 2015 by European Commission
 *
 * Licensed under the EUPL, Version 1.1 or - as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence");
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 * http://www.osor.eu/eupl/european-union-public-licence-eupl-v.1.1
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 *
 * This product combines work with different licenses. See the "NOTICE" text
 * file for details on the various modules and licenses.
 * The "NOTICE" text file is part of the distribution. Any derivative works
 * that you distribute must include a readable copy of the "NOTICE" text file.
 *
 */

package eu.stork.peps.auth;

import eu.stork.peps.auth.commons.EidasLoaCompareType;
import eu.stork.peps.auth.commons.EidasLoaLevels;
import eu.stork.peps.auth.commons.STORKAuthnRequest;
import eu.stork.peps.utils.PEPSValidationUtil;
import org.junit.Assert;
import org.junit.Test;

/**
 * @author vanegdi on 14/08/2015.
 */
public class PEPSValidationUtilTestCase {
    @Test
    public void testIsRequestLoAValid(){
        final STORKAuthnRequest request = new STORKAuthnRequest();
        Assert.assertFalse("Null check for values", PEPSValidationUtil.isRequestLoAValid(null, null));
        Assert.assertFalse("Null check for Level", PEPSValidationUtil.isRequestLoAValid(request ,null));
        Assert.assertFalse("Null check for request", PEPSValidationUtil.isRequestLoAValid(null, EidasLoaLevels.HIGH.stringValue()));
        Assert.assertFalse("Null check for request.eidasLoA", PEPSValidationUtil.isRequestLoAValid(request, EidasLoaLevels.HIGH.stringValue()));
        request.setEidasLoA(EidasLoaLevels.LOW.stringValue());
        request.setEidasLoACompareType(null);
        Assert.assertFalse("Null check for request.eidasLoACompareType", PEPSValidationUtil.isRequestLoAValid(request, EidasLoaLevels.HIGH.stringValue()));
        // Checks on minimum comparison
        request.setEidasLoACompareType(EidasLoaCompareType.MINIMUM.stringValue());
        Assert.assertTrue("Normal case LOW<=High (minimum)", PEPSValidationUtil.isRequestLoAValid(request, EidasLoaLevels.HIGH.stringValue()));
        request.setEidasLoA(EidasLoaLevels.HIGH.stringValue());
        Assert.assertTrue("Normal case HIGH<=High (minimum)", PEPSValidationUtil.isRequestLoAValid(request, EidasLoaLevels.HIGH.stringValue()));
        Assert.assertFalse("Error case HIGH<=substantial (minimum)", PEPSValidationUtil.isRequestLoAValid(request, EidasLoaLevels.SUBSTANTIAL.stringValue()));
        // Checks on exact comparison
        request.setEidasLoACompareType(EidasLoaCompareType.EXACT.stringValue());
        Assert.assertTrue("Normal case HIGH=High (exact)", PEPSValidationUtil.isRequestLoAValid(request, EidasLoaLevels.HIGH.stringValue()));
        Assert.assertFalse("Error case HIGH=Low (exact)", PEPSValidationUtil.isRequestLoAValid(request, EidasLoaLevels.LOW.stringValue()));
    }
}
