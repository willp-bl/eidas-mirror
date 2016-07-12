<%@ page contentType="text/html; charset=UTF-8"%>
<%@ taglib prefix="s" uri="/struts-tags" %>
<%@taglib prefix="e" uri="https://www.owasp.org/index.php/OWASP_Java_Encoder_Project" %>
<html>
<head>
    <meta http-equiv='pragma' content='no-cache'/>
    <meta http-equiv='cache-control' content='no-cache, no-store, must-revalidate'/>
	<meta http-equiv="Expires" content="-1"/>
	<meta http-equiv="Content-Type" content="text/html;charset=UTF-8">
	<title>STORK:: (Secure Identity Across Borders Linked)</title>
	<link href="resources/css/estilos.css" rel="stylesheet" type="text/css"/>
</head>

<body onload="document.redirectForm.submit();">
<form id="redirectForm" name="redirectForm" method="post" action="${e:forHtml(callbackUrl)}">
	<input type="hidden" id="strAttrList" name="strAttrList" value="${e:forHtml(strAttrList)}"/>
</form>
<noscript>
<div id="contenedor">

	<div id="cabecera">
		<div class="logo"></div>
		<div class="logo_ue"></div>
		<div class="tituloCabecera">STORK:: (Secure Identity Across Borders Linked)</div>
	</div>
	<div id="borde">
		<div id="principal">
			<div id="margen">
				<h2>
					<s:i18n name="eu.stork.ap.bundle">
						<s:text name="APRedirect.title"/>
					</s:i18n>
				</h2>
				<br />
				
				<s:form theme="stork" name="redirectForm" method="post" action="%{callbackUrl}">
					<s:hidden name="strAttrList" value="%{strAttrList}"/>
					<s:submit label="%{getText('accept.button')}" />
				</s:form>
			</div>
		</div>
	</div>
</div>			
</noscript>
</body>
</html>