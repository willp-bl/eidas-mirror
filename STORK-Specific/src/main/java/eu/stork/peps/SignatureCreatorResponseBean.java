package eu.stork.peps;

/**
 * Class for handling spring bean definition and use it on the servlets
 */
public class SignatureCreatorResponseBean extends SpecificCommonBean {

  /**
   * URL of C-PEPS Signature creator return handler.
   */
  private String callbackURL;

  public String getCallbackURL() {
    return callbackURL;
  }

  public void setCallbackURL(String callbackURL) {
    this.callbackURL = callbackURL;
  }
}
