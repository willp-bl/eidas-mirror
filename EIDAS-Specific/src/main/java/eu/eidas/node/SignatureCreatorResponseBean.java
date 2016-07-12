package eu.eidas.node;

/**
 * Class for handling spring bean definition and use it on the servlets
 */
public class SignatureCreatorResponseBean extends SpecificCommonBean {

  /**
   * URL of ProxyService Signature creator return handler.
   */
  private String callbackURL;

  public String getCallbackURL() {
    return callbackURL;
  }

  public void setCallbackURL(String callbackURL) {
    this.callbackURL = callbackURL;
  }
}
