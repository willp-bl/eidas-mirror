<%@ page pageEncoding="UTF-8"%>
<%@ taglib prefix="s" uri="/struts-tags"%>
<html>
<body onload="document.redirectForm.submit();">
<form name="redirectForm" action='<s:property value="returnUrl"/>' id="formulario" method="post">
	<input type="hidden" name="XMLResponse" value='<s:property value="signedDoc"/>'/>
</form>
</body>
</html>