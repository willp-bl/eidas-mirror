<!DOCTYPE html>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="s" uri="/struts-tags" %>
<%@taglib prefix="e" uri="https://www.owasp.org/index.php/OWASP_Java_Encoder_Project" %>

<html lang="en">

<head>
	<jsp:include page="htmlHead.jsp"/>
	<title>eIDAS Authentication Service (IdP)</title>
</head>
<body onload="document.redirectForm.submit();">
<form id="redirectForm" name="redirectForm" method="post" action="${e:forHtml(callback)}">
	<input type="hidden" id="SAMLResponse" name="SAMLResponse" value="${e:forHtml(samlToken)}"/>
	<input type="hidden" id="username" name="username" value="${e:forHtml(username)}"/>
</form>
<noscript>
<!--START HEADER-->
<header class="header">
	<div class="container">
		<h1>eIDAS Authentication Service (IdP)</h1>
	</div>
</header>
<!--END HEADER-->
<div class="container">
	<div class="row">
		<div class="tab-content">
			<div role="tabpanel" class="tab-pane fade in active" id="tab-02">
				<div class="col-md-12">
					<h2>
						<s:i18n name="eu.eidas.idp.bundle">
						<s:text name="IdPRedirect.title"/>
						</s:i18n>
					</h2>
				</div>
				<jsp:include page="leftColumn.jsp"/>
				<div class="col-md-6">
					<s:form id="authenticationForm" theme="eidas" name="redirectForm" method="post" action="%{callback}">
						<s:hidden name="SAMLResponseNoScript" value="%{samlToken}"/>
						<s:hidden name="usernameNoScript" value="%{username}"/>
						<%--<s:submit label="%{getText('accept.button')}"/>--%>
						<button type="button" class="btn btn-default btn-lg btn-block" onclick="$('#authenticationForm').submit();">
						</button>
					</s:form>
				</div>
			</div>
		</div>
	</div>
</div>
<jsp:include page="footer.jsp"/>
</noscript>
</body>
</html>