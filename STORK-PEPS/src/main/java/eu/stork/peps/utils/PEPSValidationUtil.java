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

package eu.stork.peps.utils;

import eu.stork.peps.auth.commons.*;
import eu.stork.peps.auth.commons.exceptions.InternalErrorPEPSException;
import eu.stork.peps.auth.engine.core.SAMLCore;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author vanegdi on 14/08/2015.
 * Remark : moved from pepsUtil
 */
public class PEPSValidationUtil {
    private PEPSValidationUtil(){
        // Privaute default constructor for utility class.
    }
    /**
     * Logger object.
     */
    private static final Logger LOG = LoggerFactory.getLogger(PEPSValidationUtil.class.getName());

    /**
     * validates the current binding with that configured in the SAMLRequest
     * @param authRequest
     * @param method
     */
    public static void validateBinding(STORKAuthnRequest authRequest, String method, PEPSErrors reportedErr){

        if(authRequest.getBinding()!=null && !authRequest.getBinding().equalsIgnoreCase(method) ||
                authRequest.getBinding()==null && !SAMLCore.EIDAS10_SAML_PREFIX.getValue().equalsIgnoreCase(authRequest.getMessageFormatName())  ){
            LOG.info("Expected auth request protocol binding {} but got {}", method, authRequest.getBinding());
            throw new InternalErrorPEPSException( PEPSUtil.getConfig(reportedErr.errorCode()), PEPSUtil.getConfig(reportedErr.errorMessage()),
                    new InternalErrorPEPSException(PEPSUtil.getConfig(PEPSErrors.INVALID_PROTOCOL_BINDING.errorCode()), PEPSUtil.getConfig(PEPSErrors.INVALID_PROTOCOL_BINDING.errorMessage())));
        }
    }
    /**
     * Check if the Level of assurance is valid
     * @param authnRequest
     * @param stringMaxLoA - max LoA value of the responder
     * @return true when the LoA value in the request exists and is inferior (or equal) to that of the responder
     */
    public static boolean isRequestLoAValid(final STORKAuthnRequest authnRequest, String stringMaxLoA){
        boolean invalidLoa = StringUtils.isEmpty(stringMaxLoA) || EidasLoaLevels.getLevel(stringMaxLoA)==null ||
                authnRequest== null || authnRequest.getEidasLoA()==null || EidasLoaLevels.getLevel(authnRequest.getEidasLoA())==null;
        if(!invalidLoa){
            if(EidasLoaCompareType.getCompareType(authnRequest.getEidasLoACompareType())==EidasLoaCompareType.MINIMUM) {
                invalidLoa = EidasLoaLevels.getLevel(authnRequest.getEidasLoA()).numericValue() > EidasLoaLevels.getLevel(stringMaxLoA).numericValue();
            }else{
                invalidLoa = EidasLoaLevels.getLevel(authnRequest.getEidasLoA()).numericValue() != EidasLoaLevels.getLevel(stringMaxLoA).numericValue();
            }
        }

        return !invalidLoa;
    }
}
