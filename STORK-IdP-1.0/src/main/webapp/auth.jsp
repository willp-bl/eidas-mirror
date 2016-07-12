<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@page import="java.util.Properties"%>
<%@page import="java.net.URL"%>
<%@page import="java.io.InputStream"%>
<%@page import="java.util.Enumeration"%>
<%@page import="eu.stork.peps.auth.commons.PEPSParameters"%>
<%
	String samlToken = request.getParameter(PEPSParameters.SAML_REQUEST.toString());
	String signAssertion = request.getParameter("signAssertion");
	String encryptAssertion = request.getParameter("encryptAssertion");
%>
<html>
<head>
    <meta http-equiv='pragma' content='no-cache'/>
    <meta http-equiv='cache-control' content='no-cache, no-store, must-revalidate'/>
	<meta http-equiv="Expires" content="-1"/>
	<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
	<title>eIDAS Authentication Service (IdP)</title>
	<link href="resources/css/estilos.css" rel="stylesheet" type="text/css"/>
</head>
<body>
<div id="contenedor">
	<div id="cabecera">
		<div class="logo"></div>
		<div class="logo_ue"></div>
		<div class="tituloCabecera">eIDAS Authentication Service (IdP)</div>
	</div>
	<div id="borde">
		<div id="principal">
			<div id="margen">

<form name="authentication" method="post" action="Login">
	<table>
		<tr>
			<td colspan="2"><h4>Authentication</h4></td>
		</tr>
		<tr>
			<td>Username: </td>
			<td><input type="text" name="username"/></td>
		</tr>
		<tr>
			<td>Password: </td>
			<td><input type="password" name="password"/></td>
		</tr>
		<c:if test="${param.messageFormat=='eidas'}">
		<tr>
			<td>Level of Assurance:</td>
			<td>
				<select name="eidasloa" id="eidasloa" >
								<option value="http://eidas.europa.eu/LoA/low">
										http://eidas.europa.eu/LoA/low</option>
								<option value="http://eidas.europa.eu/LoA/substantial">
										http://eidas.europa.eu/LoA/substantial</option>
								<option value="http://eidas.europa.eu/LoA/high">
										http://eidas.europa.eu/LoA/high</option>
				</select>		
			</td>
		</tr>
		</c:if>
		
	</table>
	<input type="hidden" name="samlToken" value="<%=samlToken%>"/>
	<input type="hidden" name="signAssertion" value="<%=signAssertion%>"/>
	<input type="hidden" name="encryptAssertion" value="<%=encryptAssertion%>"/>
	<input type="submit" value="enviar" />
</form>

			</div>
		</div>
	</div>
</div>

</body>
</html>