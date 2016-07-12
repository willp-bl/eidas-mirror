package eu.eidas.node;

/**
 * Class for handling spring bean definition and use it on the servlets
 */
public class SignatureCreatorReturnBean extends SpecificCommonBean {

  /**
   * Signed Doc attribute.
   */
  private String attribute;

  public String getAttribute() {
    return attribute;
  }

  public void setAttribute(String attribute) {
    this.attribute = attribute;
  }
}
