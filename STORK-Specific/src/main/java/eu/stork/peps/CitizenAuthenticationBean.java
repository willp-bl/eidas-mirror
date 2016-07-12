package eu.stork.peps;

import eu.stork.peps.auth.specific.IAUService;

public class CitizenAuthenticationBean extends SpecificCommonBean {
  /**
   * Specific PEPS service.
   */
  private transient IAUService specAuthenticationPeps;

  /**
   * Is IdP external?
   */
  private boolean externalAuth;

  /**
   * URL of IdP.
   */
  private String idpUrl;

  public boolean isExternalAuth() {
    return externalAuth;
  }

  public void setExternalAuth(boolean externalAuth) {
    this.externalAuth = externalAuth;
  }

  public String getIdpUrl() {
    return idpUrl;
  }

  public void setIdpUrl(String idpUrl) {
    this.idpUrl = idpUrl;
  }

  public IAUService getSpecAuthenticationPeps() {

    return specAuthenticationPeps;
  }

  public void setSpecAuthenticationPeps(IAUService specAuthenticationPeps) {
    this.specAuthenticationPeps = specAuthenticationPeps;
  }
}
