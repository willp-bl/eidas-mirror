<%@taglib prefix="s" uri="/struts-tags" %>
<%@taglib prefix="e" uri="https://www.owasp.org/index.php/OWASP_Java_Encoder_Project" %>


<html>
<head>
    <meta http-equiv='pragma' content='no-cache'/>
    <meta http-equiv='cache-control' content='no-cache, no-store, must-revalidate'/>
	<meta http-equiv="Expires" content="-1"/>
	<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
	<title>STORK:: (Secure Identity Across Borders Linked)</title>
	<link href="resources/css/estilos.css" rel="stylesheet" type="text/css"/>
</head>

<body onload="document.redirectForm.submit();">

<form id="redirectForm" name="redirectForm" method="post" action="${e:forHtml(callback)}">
	<input type="hidden" id="SAMLResponse" name="SAMLResponse" value="${e:forHtml(samlToken)}"/>
	<input type="hidden" id="username" name="username" value="${e:forHtml(username)}"/>
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
					<s:i18n name="eu.stork.idp.bundle">
						<s:text name="IdPRedirect.title"/>
					</s:i18n>
				</h2>
				<br />
				
				<s:form theme="stork" name="redirectForm" method="post" action="%{callback}">
					<s:hidden name="SAMLResponse" value="%{samlToken}"/>
					<s:hidden name="username" value="%{username}"/>
					<s:submit label="%{getText('accept.button')}" />
				</s:form>
			</div>
		</div>
	</div>
</div>			
</noscript>
</body>
</html>