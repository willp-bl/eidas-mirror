<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<%@ taglib prefix="s" uri="/struts-tags"%>
<html>
<head>
		<title>STORK:: (Sign module)</title>
		<link href="css/estilos.css" rel="stylesheet" type="text/css" />

		<script type="text/javascript" language="javascript" src="common-js/time.js"></script>
		<script type="text/javascript" language="javascript" src="common-js/instalador.js"></script>
		<script type="text/javascript" language="javascript" src="common-js/deployJava.js"></script>
		<script type="text/javascript" language="javascript" src="common-js/firma.js"></script>
		<script type="text/javascript" language="javascript" src="common-js/htmlEscape.js"></script>
		<script type="text/javascript" language="javascript" src="common-js/utils.js"></script>
		<script type="text/javascript" language="javascript" src="common-js/styles.js"></script>
		<script type="text/javascript" language="javascript" src="common-js/firmaWeb.js"></script>
		<script type="text/javascript" language="javascript" src="common-js/constantes.js"></script>
				
		<script type="text/javascript" language="javascript">
			function firmar()
			{
				//Para evitar que se pulse dos veces el bot�n (dos peticiones no es buena idea) lo inhabilitamos
				//document.getElementById("botonFirmar").disabled="disabled";
				
				// Preparamos el cliente para firmar
				/*clienteFirma.initialize();
				clienteFirma.setShowErrors(true);*/
				
				// Configuramos el proceso de firma
				/*var formato= getFormato();
				clienteFirma.setSignatureFormat(formato);
				var modo= getModo();
				clienteFirma.setSignatureMode(modo);	
				clienteFirma.setData(clienteFirma.getBase64FromText(document.getElementById('mensaje').value));
				
				// Firmamos
				//var ficheroFirmado = firmaWeb(element, document);
				clienteFirma.sign();
				
				// Recogemos el resultado (o el mensaje de error)
				if(!clienteFirma.isError())
				{
					firma = clienteFirma.getSignatureBase64Encoded();
					//firma = clienteFirma.getSignatureText();					
										
					document.getElementById('mensaje').value= firma;					
					
				}
				else
				{
					document.getElementById('mensaje').value= clienteFirma.getErrorMessage();
				} */
				//Volvemos a activar el bot�n
				document.getElementById("botonFirmar").disabled="";
				
				document.forms[0].submit();
			}		
			function getFormato()
			{
//				var selectFormato= document.getElementById('formato');
//				var valueFormato= selectFormato.options[selectFormato.selectedIndex].value;
//				return valueFormato;
				return "XADES_ENVELOPING";

			}

			function getModo()
			{
//				var selectModo= document.getElementById('modo');
//				var valueModo= selectModo.options[selectModo.selectedIndex].value;
//				return valueModo;
				return "implicit";
			}	
		</script>
</head>

<body id="fondo" onLoad="document.getElementById('mensaje').value = clienteFirma.getTextFromBase64(document.getElementById('mensaje').value);">
	<script type="text/javascript">
		//cargarAppletFirma();
	</script>
	
	
	<!-- <form action='<s:property value="returnUrl"/>' id="formulario" method="post">-->
	<form action="CreateResponseAction" id="formulario" method="post">
	
	<div class="fondocabecera">

	<div id="contenedor">
	
		<div id="cabecera">
  
           <div class="logo_min"></div>
           <div class="logo_ue"></div>
	        <div class="tituloCabecera">Plataforma de Autenticaci�n Transfronteriza</div>
            <div class="ayuda"><a href="/PEPS/ayuda.html" target="_blank" title="Ayuda">&nbsp;?</a></div>
		</div>
        
        <div class="cuerpo">
            <div class="margen">
	
			
				Atenci�n, se le solicita firmar el siguiente texto con su certificado electr�nico.<br/><br/><br/>


				<table border="0" cellpadding="2" cellspacing="2" width="100%" class="borde" align="center">
<!-- 
					<tr>
                    <td class="filatit" width="35%">FORMATO DE FIRMA ELECTR�NICA:</td>
                    <td class="filaresul">
						<select name="formato" id="formato">
							<option value="CMS">CMS</option>
							<option value="CADES">CADES</option>
							<option value="XADES">Detached XAdES</option>
							<option value="XADES_ENVELOPING" selected="selected">Enveloping XAdES</option>
							<option value="XMLDSIG_DETACHED">Detached XMLDSig</option>
							<option value="XMLDSIG_ENVELOPING">Enveloping XMLDSig</option>
						</select>
					</td>                    
                    </tr>   
                    <tr>
                    <td class="filatit" width="35%">MODO DE FIRMA ELECTR�NICA:</td>
                    <td class="filaresul">
						<select name="modo" id="modo">
							<option value="explicit">Explicita</option>
							<option value="implicit" selected="selected">Implicita</option>
						</select>
					</td>
                    </tr>  
 -->                    <tr>
                    <td class="filatit" width="35%">Mensaje a firmar:</td>
                    <td class="filaresul">
                    	<textarea name="XMLResponse" id="mensaje" class="formens" cols="60" rows="5" readonly><s:property value="textToSign"/></textarea> </td>
                   
                    </tr>                          
                </table>
                <input type="hidden" name="requestId" value='<s:property value="requestId"/>'/>
				<div class="botones">
					<input name="btnFirmar" id="botonFirmar" value="Firmar formulario" type="button" onclick="firmar()" class="submit" />
				</div>   
	
	
			<div id="space"></div>
			
			    </div><!--fin cuerpo-->
        </div><!--fin margen-->
        
         <div class="cierre">
         <div class="logo"></div>
        </div>
	
	
	</div>
	</form>	
</body>
</html>

