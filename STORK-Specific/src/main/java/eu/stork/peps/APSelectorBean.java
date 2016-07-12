package eu.stork.peps;

import eu.stork.peps.auth.specific.IAUService;

/**
 * Class for handling spring bean definition and use it on the servlets
 */
public class APSelectorBean extends SpecificCommonBean {

  /**
   * URL of AP.
   */
  private String apUrl;

  // injected by Spring
  /**
   * Specific PEPS service.
   */
  private transient IAUService specificPeps;

  /**
   * Is the AP external?
   */
  private boolean externalAP;

  /**
   * Does the Signature module exists?
   */
  private boolean sigModuleExists;

  /**
   * Number of APs?
   */
  private int numberOfAps;

  /**
   * URL of C-PEPS AP response handler.
   */
  private String callbackURL;


  /**
   * Signed Doc attribute.
   */
  private String attribute;

  /**
   * Signed Doc data.
   */
  private String data;

  /**
   * Signed Doc Data URL.
   */
  private String dataURL;

  /**
   * Signature Creator Module URL.
   */
  private String sigCreatorModuleURL;

  /**
   * Setter for externalAP.
   *
   * @param externalAP The externalAP to set.
   */
  public void setExternalAP(final boolean externalAP) {
    this.externalAP = externalAP;
  }

  /**
   * Getter for externalAP.
   *
   * @return The externalAP value.
   */
  public boolean isExternalAP() {
    return externalAP;
  }

  /**
   * Setter for specificPeps.
   *
   * @param specificPeps The specificPeps to set.
   */
  public void setSpecificPeps(final IAUService specificPeps) {
    this.specificPeps = specificPeps;
  }

  /**
   * Getter for specificPeps.
   *
   * @return The specificPeps value.
   */
  public IAUService getSpecificPeps() {
    return specificPeps;
  }

  /**
   * Setter for numberOfAps.
   *
   * @param numberOfAps The numberOfAps to set.
   */
  public void setNumberOfAps(final int numberOfAps) {
    this.numberOfAps = numberOfAps;
  }

  /**
   * Getter for numberOfAps.
   *
   * @return The numberOfAps value.
   */
  public int getNumberOfAps() {
    return numberOfAps;
  }

  /**
   * Setter for callbackURL.
   *
   * @param callbackURL The callbackURL to set.
   */
  public void setCallbackURL(final String callbackURL) {
    this.callbackURL = callbackURL;
  }

  /**
   * Getter for callbackURL.
   *
   * @return The callbackURL value.
   */
  public String getCallbackURL() {
    return callbackURL;
  }

  /**
   * Setter for apUrl.
   *
   * @param apUrl The apUrl to set.
   */
  public void setApUrl(final String apUrl) {
    this.apUrl = apUrl;
  }

  /**
   * Getter for apUrl.
   *
   * @return The apUrl value.
   */
  public String getApUrl() {
    return apUrl;
  }

  /**
   * Setter for Signed Doc attribute.
   *
   * @param attribute The signed doc to set.
   */
  public void setAttribute(final String attribute) {
    this.attribute = attribute;
  }

  /**
   * Getter for Signed Doc attribute.
   *
   * @return The signed doc value.
   */
  public String getAttribute() {
    return attribute;
  }

  /**
   * Setter for Signed Doc data.
   *
   * @param data The signed doc data.
   */
  public void setData(final String data) {
    this.data = data;
  }

  /**
   * Getter for Signed Doc data.
   *
   * @return The signed doc data.
   */
  public String getData() {
    return data;
  }

  /**
   * Setter for Signed Doc dataURL.
   *
   * @param dataURL the dataURL to set.
   */
  public void setDataURL(final String dataURL) {
    this.dataURL = dataURL;
  }

  /**
   * Getter for Signed Doc dataURL.
   *
   * @return the dataURL value.
   */
  public String getDataURL() {
    return dataURL;
  }

  /**
   * Setter for sigCreatorModuleURL.
   *
   * @param sigModURL the sigCreatorModuleURL to set.
   */
  public void setSigCreatorModuleURL(final String sigModURL) {
    this.sigCreatorModuleURL = sigModURL;
  }

  /**
   * Getter for sigCreatorModuleURL
   *
   * @return The sigCreatorModuleURL value.
   */
  public String getSigCreatorModuleURL() {
    return sigCreatorModuleURL;
  }

  /**
   * Setter for sigModuleExists.
   *
   * @param sigModuleExists The sigModuleExists to set.
   */
  public void setSigModuleExists(final boolean sigModuleExists) {
    this.sigModuleExists = sigModuleExists;
  }

  /**
   * Getter for sigModuleExists.
   *
   * @return The sigModuleExists value.
   */
  public boolean isSigModuleExists() {
    return sigModuleExists;
  }
}
