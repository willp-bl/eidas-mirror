<!DOCTYPE html>
<%@ page contentType="text/html; charset=UTF-8"%>
<%@ taglib prefix="s" uri="/struts-tags"%>
<html>
<head>
    <meta http-equiv='pragma' content='no-cache'/>
    <meta http-equiv='cache-control' content='no-cache, no-store, must-revalidate'/>
	<meta http-equiv="Expires" content="-1"/>
	<title><s:property value="%{getText('tituloId')}"/></title>
	<script type="text/javascript" src="js/script.js"></script>
    <script type="text/javascript" src="js/jquery-1.11.1.min.js"></script>
	<script type="text/javascript" src="js/dd-min.js"></script>
    <link href="css/estilos.css" rel="stylesheet" type="text/css" />
    <link href="css/dd.css" rel="stylesheet" type="text/css" />

</head>

<body>

<div id="contenedor">
<div id="cabecera">
<div class="logo"></div>
<div class="tituloCabecera"><s:property value="%{getText('tituloCabeceraId')}"/></div>
</div>
<div id="borde">
<div id="principal">
<div id="margen">




<div class="tabs"><!-- tabs -->
<ul class="tabNavigation">
	<li><a href="#tab201"><s:property value="%{getText('tab1Id')}"/></a></li>
	<li><a href="#tab2"><s:property value="%{getText('tab2Id')}"/></a></li>
	<li><a href="#tab3"><s:property value="%{getText('tab3Id')}"/></a></li>
</ul>

<!-- tab containers -->
<div id="tab201">

<!-- ******************************************************************************************************************************** -->
<!-- ***************************************************************TABBED PANEL 1*************************************************** -->
<!-- ******************************************************************************************************************************** -->
<h1><s:property value="%{providerName}" /> <s:property value="%{getText('storkMode')}"/></h1>
<br />
<s:form action="IndexPage">
	<table border="0" cellpadding="3" cellspacing="3" width="100%">
	
		<tr id="altura">
			<td>
			<h2><s:property value="%{getText('spCountryId')}"/>:</h2>
			</td>
			<td width="24%">
			<div id="designhtml">
                <select name="speps" id="speps" class="flagsSelect">
                    <option data-description="Choose an option"></option>
                    <s:iterator value="countries">
                        <option value="<s:property value="url"/>" data-image="img/banderas/<s:property value="name"/>.gif"><s:property
                            value="name" /></option>
                    </s:iterator>
			    </select>
            </div>

			</td>
			<td><input type="text" name="pepsUrl" value="" id="input" /></td>
		</tr>

		<tr id="altura">
			<td width="16%">
			<h2><s:property value="%{getText('citizenCountryId')}"/>:</h2>
			</td>
			<td colspan="2">
			<div id="designhtm"><select name="citizen" id="citizen" class="flagsSelect">
                <option data-description="Choose an option"></option>
				<s:iterator value="countries">
					<option value="<s:property value="name" />"
                            data-image="img/banderas/<s:property value="name"/>.gif"><s:property
						value="name" /></option>
				</s:iterator>
			</select></div>
			</td>
		</tr>


		<tr id="altura">
			<td>
			<h2><s:property value="%{getText('spReturnUrlId')}"/>:</h2>
			</td>
			<td colspan="2"><s:textfield name="returnUrl" id="input" /></td>
		</tr>


		<tr id="altura">
			<td>
			<h2><s:property value="%{getText('qaaLevelId')}"/>:</h2>
			</td>

			<td colspan="2"><s:textfield key="qaa" id="input" /></td>
		</tr>

		<tr id="altura">
			<td>
					<h2><s:property value="%{getText('attributesId')}"/>:</h2>
			</td>
			<td colspan="2"><b>
					<input type="radio" name="allType" id="check_all_Mandatory" value="true" />
					<label for="check_all_Mandatory"><s:property value="%{getText('mandatoryId')}"/></label>
					
					<input type="radio" name="allType" id="check_all_Optional" value="false" checked="checked" />
					<label for="check_all_Optional"><s:property value="%{getText('optionalId')}"/></label>
					
					<input type="radio" name="allType" id="check_all_NoRequest" value="none" />
					<label for="check_all_NoRequest"><s:property value="%{getText('doNotRequestId')}"/></label>
					</b>
			</td>
		</tr>
						
			<s:iterator value="storkAttributeList">

				<tr id="altura">
					<s:if test="%{value[0]!=''}">
						<td>
							<input type="text" name="<s:property value="name"/>" value="<s:property value="name"/>" id="input" /> 
							<input type="text" name="<s:property value="name"/>Value" value="<s:property value="value[0]"/>" id="input" />
						</td>
					</s:if>
					<s:else>
						<td>
							<input type="text" name="<s:property value="name"/>" value="<s:property value="name"/>" id="input" />
						</td>
					</s:else>
					<td colspan="2">
					
					<input type="radio" name="<s:property value="name" />Type" id="Mandatory_<s:property value="name" />" value="true" />
					<label for="Mandatory_<s:property value="name" />"><s:property value="%{getText('mandatoryId')}"/></label> 
					
					<input type="radio" name="<s:property value="name" />Type" id="Optional_<s:property value="name" />" value="false" checked="checked" />
					<label for="Optional_<s:property value="name" />"><s:property value="%{getText('optionalId')}"/></label> 
					
					<input type="radio" name="<s:property value="name" />Type" id="NoRequest_<s:property value="name" />" value="none" />
					<label for="NoRequest_<s:property value="name" />"><s:property value="%{getText('doNotRequestId')}"/></label>
					
					</td>
				</tr>
			</s:iterator></td>
		</tr>
		<tr>
			<td colspan="3">
			<div id="botones">
				<input type="submit" value="Submit" />
			</div>
			</td>
		</tr>
		<tr>
			<td colspan="3"><s:fielderror /></td>
		</tr>
	</table>

</s:form></p>
</div>

	<div id="tab2">

		<!-- ******************************************************************************************************************************** -->
		<!-- ***************************************************************TABBED PANEL 2 EIDAS attributes*************************************************** -->
		<!-- ******************************************************************************************************************************** -->
		<h1><s:property value="%{providerName}" /> <s:property value="%{getText('eIDASMode')}"/></h1>
		<br />
		<s:form action="IndexPage">
			<table border="0" cellpadding="3" cellspacing="3" width="100%">

				<tr id="altura">
					<td>
						<h2><s:property value="%{getText('spCountryId')}"/>:</h2>
					</td>
					<td width="24%">
						<div id="designhtml">
							<select name="spepseidas" id="spepseidas" class="flagsSelect">
								<option data-description="Choose an option"></option>
								<s:iterator value="countries">
									<option value="<s:property value="url"/>" data-image="img/banderas/<s:property value="name"/>.gif"><s:property
											value="name" /></option>
								</s:iterator>
							</select>
						</div>

					</td>
					<td><input type="text" name="pepsUrl" value="" id="input" /></td>
				</tr>

				<tr id="altura">
					<td width="16%">
						<h2><s:property value="%{getText('citizenCountryId')}"/>:</h2>
					</td>
					<td colspan="2">
						<div id="designhtm"><select name="citizenEidas" id="citizeneidas" class="flagsSelect">
							<option data-description="Choose an option"></option>
							<s:iterator value="countries">
								<option value="<s:property value="name" />"
										data-image="img/banderas/<s:property value="name"/>.gif"><s:property
										value="name" /></option>
							</s:iterator>
						</select></div>
					</td>
				</tr>


				<tr id="altura">
					<td>
						<h2><s:property value="%{getText('spReturnUrlId')}"/>:</h2>
					</td>
					<td colspan="2"><s:textfield name="returnUrl" id="input" /></td>
				</tr>


				<tr id="altura">
					<td>
						<h2><s:property value="%{getText('eidasNameIdentifier')}"/>:</h2>
					</td>

					<td colspan="2">
						<select name="eidasNameIdentifier" id="eidasNameIdentifier" >
							<option value="label">Choose a value</option>
							<option value="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">
								persistent</option>
							<option value="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">
								transient</option>
							<option selected value="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">
								unspecified</option>
						</select>
					</td>
				</tr>
				<tr id="altura">
					<td>
						<h2><s:property value="%{getText('eidasLoAId')}"/>:</h2>
					</td>
					<td colspan="2"><select name="eidasloa" id="eidasloa" >
							<option value="label">Choose a value</option>
								<option selected value="http://eidas.europa.eu/LoA/low">
										http://eidas.europa.eu/LoA/low</option>
								<option value="http://eidas.europa.eu/LoA/substantial">
										http://eidas.europa.eu/LoA/substantial</option>
								<option value="http://eidas.europa.eu/LoA/high">
										http://eidas.europa.eu/LoA/high</option>
						</select></td>
				</tr>

				<tr id="altura">
					<td>
						<h2><s:property value="%{getText('eidasloaCompareType')}"/>:</h2>
					</td>
					<td colspan="2"><select name="eidasloaCompareType" id="eidasloaCompareType" >
								<option value="minimum" selected>minimum</option>
								<option value="exact">exact</option>
						</select></td>
				</tr>

				<tr id="altura">
					<td>
						<h2><s:property value="%{getText('eidasSPType')}"/>:</h2>
					</td>
					<td colspan="2"><select name="eidasSPType" id="eidasSPType" >
								<option value="public" selected>public</option>
								<option value="private">private</option>
						</select></td>
				</tr>

				<tr id="altura">
					<td>
						<h2><s:property value="%{getText('eidasAttributesId')}"/>:</h2>
					</td>
					<td colspan="2"><b>
						<input type="radio" name="allTypeEidas" id="check_all_MandatoryEidas" value="true" />
						<label for="check_all_MandatoryEidas"><s:property value="%{getText('mandatoryId')}"/></label>

						<input type="radio" name="allTypeEidas" id="check_all_OptionalEidas" value="false" checked="checked" />
						<label for="check_all_OptionalEidas"><s:property value="%{getText('optionalId')}"/></label>

						<input type="radio" name="allTypeEidas" id="check_all_NoRequestEidas" value="none" />
						<label for="check_all_NoRequestEidas"><s:property value="%{getText('doNotRequestId')}"/></label>
					</b>
					</td>
				</tr>

				<s:iterator value="eidasAttributeList">

					<tr id="altura">
						<s:if test="%{value[0]!=''}">
							<td>
								<input type="text" name="<s:property value="name"/>" value="<s:property value="name"/>" id="input" />
								<input type="text" name="<s:property value="name"/>Value" value="<s:property value="value[0]"/>" id="input" />
							</td>
						</s:if>
						<s:else>
							<td>
								<input type="text" name="<s:property value="name"/>" value="<s:property value="name"/>" id="input" />
							</td>
						</s:else>
						<td colspan="2">

							<input type="radio" name="<s:property value="name" />Type" id="Mandatory_<s:property value="name" />Eidas" value="true" />
							<label for="Mandatory_<s:property value="name" />Eidas"><s:property value="%{getText('mandatoryId')}"/></label>

							<input type="radio" name="<s:property value="name" />Type" id="Optional_<s:property value="name" />Eidas" value="false" checked="checked" />
							<label for="Optional_<s:property value="name" />Eidas"><s:property value="%{getText('optionalId')}"/></label>

							<input type="radio" name="<s:property value="name" />Type" id="NoRequest_<s:property value="name" />Eidas" value="none" />
							<label for="NoRequest_<s:property value="name" />Eidas"><s:property value="%{getText('doNotRequestId')}"/></label>

						</td>
					</tr>
				</s:iterator>
				</tr>
				<tr>
					<td colspan="3">
						<div id="botones">
							<input type="submit" value="Submit" />
						</div>
					</td>
				</tr>
				<tr>
					<td colspan="3"><s:fielderror /></td>
				</tr>
			</table>
            <input type="hidden" id="spType" name="spType" value="public">

		</s:form>
	</div>


<div id="tab3">
<!-- ******************************************************************************************************************************** -->
<!-- ***************************************************************TABBED PANEL 3*************************************************** -->
<!-- ******************************************************************************************************************************** -->
<h1><s:property value="%{providerName}" /> <s:property value="%{getText('storkMode')}"/></h1>
<br />
<s:form action="redirectIndexPage">
	<table border="0" cellpadding="3" cellspacing="3" width="100%">

		<tr id="altura">
			<td width="16%">
			<h2><s:property value="%{getText('countrySelectorId')}"/>:</h2>
			</td>
			<td width="24%">
			<div id="designhtml2"><select name="speps2" id="speps2" class="flagsSelect">
                <option data-description="Choose an option"></option>
				<s:iterator value="countries">
					<option value="<s:property value="countrySelector"/>"
						data-image="img/banderas/<s:property value="name"/>.gif"><s:property
						value="name" /></option>
				</s:iterator>
			</select></div>

			</td>
			<td><input type="text" name="pepsUrl2" value="" id="input" /></td>
		</tr>

		<tr id="altura">
			<td>
			<h2><s:property value="%{getText('spReturnUrlId')}"/>:</h2>
			</td>
			<td colspan="2"><s:textfield name="returnUrl" id="input" /></td>
		</tr>


		<tr id="altura">
			<td>
			<h2>QAA LEVEL:</h2>
			</td>

			<td colspan="2"><s:textfield key="qaa" id="input" /></td>
		</tr>

		<tr id="altura">
			<td>
					<h2><s:property value="%{getText('attributesId')}"/>:</h2>
			</td>
			<td colspan="2"><b>
					<input type="radio" name="allType2" id="check_all_Mandatory2" value="true" />
					<label for="check_all_Mandatory2"><s:property value="%{getText('mandatoryId')}"/></label>
					
					<input type="radio" name="allType2" id="check_all_Optional2" value="false" checked="checked" />
					<label for="check_all_Optional2"><s:property value="%{getText('optionalId')}"/></label>
					
					<input type="radio" name="allType2" id="check_all_NoRequest2" value="none" />
					<label for="check_all_NoRequest2"><s:property value="%{getText('doNotRequestId')}"/></label>
					</b>
			</td>
		</tr>
		
			<s:iterator value="storkAttributeList">

				<tr id="altura">
					<s:if test="%{value[0]!=''}">
						<td>
							<input type="text" name="<s:property value="name"/>" value="<s:property value="name"/>" id="input" /> 
							<input type="text" name="<s:property value="name"/>Value" value="<s:property value="value[0]"/>" id="input" />
						</td>
					</s:if>
					<s:else>
						<td><input type="text" name="<s:property value="name"/>"
							value="<s:property value="name"/>" id="input" /></td>
					</s:else>
					<td colspan="2"><input type="radio"
						name="<s:property value="name" />Type"
						id="2Mandatory_<s:property value="name" />" value="true" /><label
						for="2Mandatory_<s:property value="name" />"><s:property value="%{getText('mandatoryId')}"/></label> <input
						type="radio" name="<s:property value="name" />Type"
						id="2Optional_<s:property value="name" />" value="false" checked="checked" /><label
						for="2Optional_<s:property value="name" />"><s:property value="%{getText('optionalId')}"/></label> <input
						type="radio" name="<s:property value="name" />Type"
						id="2NoRequest_<s:property value="name" />" value="none"/><label
						for="2NoRequest_<s:property value="name" />"><s:property value="%{getText('doNotRequestId')}"/></label>
					</td>
				</tr>
			</s:iterator></td>
		</tr>
		<tr>
			<td colspan="3">
			<div id="botones"><input type="submit" value="Submit" /></div>
			</td>
		</tr>
		<tr>
			<td colspan="3"><s:fielderror /></td>
		</tr>
	</table>

</s:form></p>
</div>
</div>

</div>
</div>
</div>
</div>
<script type="text/javascript" src="js/sp.js"></script>
</body>
</html>
