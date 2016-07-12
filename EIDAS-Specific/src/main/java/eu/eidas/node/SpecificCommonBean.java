package eu.eidas.node;

import eu.eidas.auth.commons.IEIDASSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Class for handling spring bean definition and use it on the servlets
 */
public class SpecificCommonBean {
  private static final Logger LOG = LoggerFactory.getLogger(SpecificCommonBean.class.getName());

  private IEIDASSession session;

  /**
   * Setter for the session object.
   * @param nSession The new session value.
   * @see IEIDASSession
   */
  public final void setSession(final IEIDASSession nSession) {
    if (nSession != null){
      this.session = nSession;
    }
    LOG.debug("== SESSION : setSession Called, size is " + this.session.size());
  }

  /**
   * Getter for the session object.
   * @return The session object.
   * @see IEIDASSession
   */
  public final IEIDASSession getSession() {
    return session;
  }


}
