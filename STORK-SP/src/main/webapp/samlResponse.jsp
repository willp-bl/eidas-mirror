<%@ page contentType="text/html; charset=UTF-8" %>
<%@ taglib prefix="s" uri="/struts-tags" %>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html>
<head>
    <meta http-equiv='pragma' content='no-cache'/>
    <meta http-equiv='cache-control' content='no-cache, no-store, must-revalidate'/>
	<meta http-equiv="Expires" content="-1"/>
	<title><s:property value="%{getText('tituloId')}"/></title>
	<script type="text/javascript" src="js/script.js"></script>
	<script type="text/javascript" src="js/base64.js"></script>
	<link href="css/estilos.css" rel="stylesheet" type="text/css"/>
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

<h1><s:property value="%{providerName}"/></h1>
<h2><s:property value="%{getText('samlResponseRecivedId')}"/></h2>
<div id="space"></div>

		<table border="0" cellpadding="1" cellspacing="1" class="borde" width="100%">
			<tr>
			<form id="countrySelector" name="countrySelector" action="populateReturnPage" target="_parent" method="post">
				<td class="tdLabel">
				<s:property value="%{getText('SAMLResponseId')}"/></td>
				<td><textarea name="SAMLResponse" cols="80" rows="5"><s:property value="SAMLResponse"/></textarea></td>
				</tr>
				<tr><td colspan=2>
				<div id="botones">
					<input type="submit" value="Submit"/>
				</div>
			</form>
			<form>
			<div id="botones">
				<input type="button" value="Encode" OnClick=encodeSAMLResponse(); />
				<input type="button" value="Decode" OnClick=decodeSAMLResponse(); />
			</div>		
			<div id="space"></div>
			</td></tr>	
			<tr><td class="tdLabel">
			<s:property value="%{getText('SAMLResponseXMLId')}"/></td>
			<td><textarea name="samlResponseXML" cols="80" rows="20"><s:property value="samlResponseXML"/></textarea>
			</td></tr>
			<tr><td>
			<s:fielderror />
			</td></tr>
			</form>
		</table>
			
			</div>
		</div>
	</div>
</div>
</body>	
</html>
