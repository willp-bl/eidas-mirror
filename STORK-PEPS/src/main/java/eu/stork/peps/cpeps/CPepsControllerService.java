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

package eu.stork.peps.cpeps;

import eu.stork.peps.auth.commons.IStorkSession;
import eu.stork.peps.auth.cpeps.ICPEPSService;
import eu.stork.peps.logging.LoggingMarkerMDC;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CPepsControllerService {
    private static final Logger LOG = LoggerFactory.getLogger(CPepsControllerService.class.getName());

    private IStorkSession session;
    private boolean askConsentType;
    private String citizenConsentUrl;
    private String callBackURL;


    /**
     * Setter for the session object.
     * @param nSession The new session value.
     * @see IStorkSession
     */
    public final void setSession(final IStorkSession nSession) {
        if (nSession != null){
            this.session = nSession;
        }
        LOG.info(LoggingMarkerMDC.SESSION_CONTENT, "CPEPS STORK-SESSION : setting a new session, size is " + this.session.size());
    }

    /**
     * Getter for the session object.
     * @return The session object.
     * @see IStorkSession
     */
    public final IStorkSession getSession() {
        return session;
    }

    public boolean isAskConsentType() {
        return askConsentType;
    }

    public void setAskConsentType(boolean askConsentType) {
        this.askConsentType = askConsentType;
    }

    public String getCitizenConsentUrl() {
        return citizenConsentUrl;
    }

    public void setCitizenConsentUrl(String citizenConsentUrl) {
        this.citizenConsentUrl = citizenConsentUrl;
    }

    public String getCallBackURL() {
        return callBackURL;
    }

    public void setCallBackURL(String callBackURL) {
        this.callBackURL = callBackURL;
    }

    /**
     * S-PEPS service.
     */
    private transient ICPEPSService cpepsService;

    public ICPEPSService getCpepsService() {
        return cpepsService;
    }

    public void setCpepsService(ICPEPSService cpepsService) {
        this.cpepsService = cpepsService;
    }

    @Override
    public String toString() {
        return "SPepsControllerService{" +
                "askConsentType=" + askConsentType +
                ", citizenConsentUrl='" + citizenConsentUrl + '\'' +
                ", cpepsService=" + cpepsService +
                ", callBackURL=" + callBackURL +
                ", session=" + session +
                '}';
    }
}
