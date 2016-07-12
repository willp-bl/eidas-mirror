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
		<br/>
		<h2><s:property value="%{getText('loginSucceededId')}"/></h2>
		<div id="space"></div>
		<h2><s:property value="%{getText('requestedDataId')}"/>:</h2>
		<div id="space"></div>
		<table class="tabla" colpadding="4">
			<tr class="filatit">
					<td>
						<s:property value="%{getText('attributeId')}"/>
					</td>
					<td>
						<s:property value="%{getText('valuesId')}"/>
					</td>
					<td>
						<s:property value="%{getText('complexValuesId')}"/>
					</td>
					<td>
						<s:property value="%{getText('statusId')}"/>
					</td>
			</tr>
			<s:iterator value="attrList" status="idx">
				<tr class="filaresult">
					<td>
						<s:property value="attrList[#idx.index].name" />
					</td>
					<td>
						<s:property value="attrList[#idx.index].value" />
					</td>
					<td>
						<s:property value="attrList[#idx.index].complexValue" />
					</td>					
					<td>
						<s:property value="attrList[#idx.index].status" />
					</td>
				</tr>
			</s:iterator>
		</table>
		<p>
			<s:property value="%{getText('errorMessage1Id')}"/><a href="."><s:property value="%{getText('errorMessage2Id')}"/> </a><s:property value="%{getText('errorMessage3Id')}"/>	
		</p>
			</div>
		</div>
	</div>
</div>


</body>
</html>