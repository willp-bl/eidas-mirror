package eu.eidas.node;

public enum SpecificParameterNames {
  ATTRIBUTE_LIST("attrList"),
  STR_ATTR_LIST("strAttrList"),
  CALLBACK_URL("callbackURL"),
  DATA("data"),
  DATA_URL("DataURL"),
  SIG_MODULE_CREATOR_URL("sigCreatorModuleURL"),
  SAML_TOKEN("samlToken"),
  IDP_URL("idpUrl"),
    IDP_SIGN_ASSERTION("idpSignAssertion")
    ;


  /**
   * constant name.
   */
  private String name;

  /**
   * Constructor
   * @param name name of the bean
   */
  SpecificParameterNames(final String name){
    this.name = name;
  }

  @Override
  public String toString() {
    return name;

  }

}
