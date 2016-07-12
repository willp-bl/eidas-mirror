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

package eu.stork.encryption;

import eu.stork.encryption.exception.MarshallException;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.util.XMLObjectHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.Charset;

/**
 * Created by bodabel on 09/01/2015.
 */
public class SAMLResponseLogHelper {

    private static final Logger LOGGER = LoggerFactory
            .getLogger(SAMLResponseLogHelper.class.getName());

    private static ThreadLocal<Boolean> logHelperOn = new ThreadLocal<Boolean>();

    private static ThreadLocal<Response> beforeEncryptionSAMLResponse = new ThreadLocal<Response>();
    private static ThreadLocal<Response> afterEncryptionSAMLResponse = new ThreadLocal<Response>();

    private static ThreadLocal<Response> beforeDecryptionSAMLResponse = new ThreadLocal<Response>();
    private static ThreadLocal<Response> afterDecryptionSAMLResponse = new ThreadLocal<Response>();

    public static void setLogHelperOn(boolean isOn) {
        logHelperOn.set(isOn);
    }

    private static boolean isLogHelperOn() {
        return logHelperOn.get() != null && logHelperOn.get();
    }

    private SAMLResponseLogHelper(){
        //hiding constructor
    }
    public static void setBeforeEncryptionSAMLResponse(Response response) {
        if (isLogHelperOn()) {
            LOGGER.trace("setBeforeEncryptionSAMLResponse");
            try {
                beforeEncryptionSAMLResponse.set(XMLObjectHelper.cloneXMLObject(response));
            } catch (MarshallingException e) {
                LOGGER.info("SAMLResponseLogHelper Error", e.getMessage());
                LOGGER.debug("SAMLResponseLogHelper Error", e);
            } catch (UnmarshallingException e) {
                LOGGER.info("SAMLResponseLogHelper Error", e.getMessage());
                LOGGER.debug("SAMLResponseLogHelper Error", e);
            }
        }
    }

    public static String getBeforeEncryptionSAMLResponseMarshalled() {
        Response response = getBeforeEncryptionSAMLResponse();
        if(response!=null){
            try {
                return new String(MarshallingUtil.marshall(response), Charset.forName("UTF-8"));
            } catch (MarshallException e) {
                LOGGER.info("SAMLResponseLogHelper Error", e.getMessage());
                LOGGER.debug("SAMLResponseLogHelper Error", e);
            }
        }
        return null;
    }

    private static Response getBeforeEncryptionSAMLResponse() {
        if (isLogHelperOn()) {
            LOGGER.trace("getBeforeEncryptionSAMLResponse");
            return beforeEncryptionSAMLResponse.get();
        }
        return null;
    }

    public static void setAfterEncryptionSAMLResponse(Response response) {
        if (isLogHelperOn()) {
            LOGGER.debug("setAfterEncryptionSAMLResponse");
            try {
                afterEncryptionSAMLResponse.set(XMLObjectHelper.cloneXMLObject(response));
            } catch (MarshallingException e) {
                LOGGER.info("SAMLResponseLogHelper Error", e);
            } catch (UnmarshallingException e) {
                LOGGER.info("SAMLResponseLogHelper Error", e);
            }
        }
    }

    public static String getAfterEncryptionSAMLResponseMarshalled() {
        Response response = getAfterEncryptionSAMLResponse();
        if(response!=null){
            try {
                return new String(MarshallingUtil.marshall(response), Charset.forName("UTF-8"));
            } catch (MarshallException e) {
                LOGGER.info("SAMLResponseLogHelper Error", e.getMessage());
                LOGGER.debug("SAMLResponseLogHelper Error", e);
            }
        }
        return null;
    }

    private static Response getAfterEncryptionSAMLResponse() {
        if (isLogHelperOn()) {
            LOGGER.trace("getAfterEncryptionSAMLResponse");
            return afterEncryptionSAMLResponse.get();
        }
        return null;
    }

    public static void setBeforeDecryptionSAMLResponse(Response response) {
        if (isLogHelperOn()) {
            LOGGER.trace("setBeforeDecryptionSAMLResponse");
            try {
                beforeDecryptionSAMLResponse.set(XMLObjectHelper.cloneXMLObject(response));
            } catch (MarshallingException e) {
                LOGGER.info("SAMLResponseLogHelper Error", e.getMessage());
                LOGGER.debug("SAMLResponseLogHelper Error", e);
            } catch (UnmarshallingException e) {
                LOGGER.info("SAMLResponseLogHelper Error", e.getMessage());
                LOGGER.debug("SAMLResponseLogHelper Error", e);
            }
        }
    }

    public static String getBeforeDecryptionSAMLResponseMarshalled() {
        Response response = getBeforeDecryptionSAMLResponse();
        if(response!=null){
            try {
                return new String(MarshallingUtil.marshall(response), Charset.forName("UTF-8"));
            } catch (MarshallException e) {
                LOGGER.debug("SAMLResponseLogHelper Error", e);
                LOGGER.info("SAMLResponseLogHelper Error", e.getMessage());
            }
        }
        return null;
    }

    private static Response getBeforeDecryptionSAMLResponse() {
        if (isLogHelperOn()) {
            LOGGER.trace("getBeforeDecryptionSAMLResponse");
            return beforeDecryptionSAMLResponse.get();
        }
        return null;
    }

    public static void setAfterDecryptionSAMLResponse(Response response) {
        if (isLogHelperOn()) {
            LOGGER.trace("setAfterDecryptionSAMLResponse");
            try {
                afterDecryptionSAMLResponse.set(XMLObjectHelper.cloneXMLObject(response));
            } catch (MarshallingException e) {
                LOGGER.info("SAMLResponseLogHelper Error", e.getMessage());
                LOGGER.debug("SAMLResponseLogHelper Error", e);
            } catch (UnmarshallingException e) {
                LOGGER.info("SAMLResponseLogHelper Error", e.getMessage());
                LOGGER.debug("SAMLResponseLogHelper Error", e);
            }
        }
    }

    public static String getAfterDecryptionSAMLResponseMarshalled() {
        Response response = getAfterDecryptionSAMLResponse();
        if(response!=null){
            try {
                return new String(MarshallingUtil.marshall(response), Charset.forName("UTF-8"));
            } catch (MarshallException e) {
                LOGGER.error("SAMLResponseLogHelper Error", e);
            }
        }
        return null;
    }

    private static Response getAfterDecryptionSAMLResponse() {
        if (isLogHelperOn()) {
            LOGGER.debug("getAfterDecryptionSAMLResponse");
            return afterDecryptionSAMLResponse.get();
        }
        return null;
    }

    public static void clearUp() {
        if (isLogHelperOn()) {
            beforeEncryptionSAMLResponse.remove();
            afterEncryptionSAMLResponse.remove();
            beforeDecryptionSAMLResponse.remove();
            afterDecryptionSAMLResponse.remove();
        }
    }
}
