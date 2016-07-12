<!DOCTYPE html>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="s" uri="/struts-tags" %>
<%@taglib prefix="e" uri="https://www.owasp.org/index.php/OWASP_Java_Encoder_Project" %>

<html lang="en">

<head>
	<jsp:include page="htmlHead.jsp"/>
	<title>eIDAS Attribute Provider (AP)</title>
</head>

<body onload="document.redirectForm.submit();">
<form id="redirectForm" name="redirectForm" method="post" action="${e:forHtml(callbackUrl)}">
	<input type="hidden" id="strAttrList" name="strAttrList" value="${e:forHtml(strAttrList)}"/>
</form>
<noscript>
!--START HEADER-->
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
						<s:i18n name="eu.eidas.ap.bundle">
							<s:text name="APRedirect.title"/>
						</s:i18n>
					</h2>
				</div>
				<jsp:include page="leftColumn.jsp"/>
				<div class="col-md-6">
					<s:form id="redirectForm" theme="eidas" name="redirectForm" method="post" action="%{callbackUrl}">
						<s:hidden name="strAttrList" value="%{strAttrList}"/>
						<button type="button" class="btn btn-default btn-lg btn-block" onclick="$('#redirectForm').submit();">
						<%--<s:submit label="%{getText('accept.button')}" />--%>
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