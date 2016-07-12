<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<fmt:setBundle basename="eu.stork.peps.package" var="i18n_eng"/>
<%@taglib prefix="e" uri="https://www.owasp.org/index.php/OWASP_Java_Encoder_Project" %>
    <meta http-equiv='pragma' content='no-cache'/>
    <meta http-equiv='cache-control' content='no-cache, no-store, must-revalidate'/>
	<meta http-equiv="Expires" content="-1"/>

<body>
	<div id="container">

		<div id="header">
			<div class="logo"></div>
			<div class="logo_ue"></div>
			<div class="headerTitle">
				<fmt:message key="stork.title" bundle="${i18n_eng}"/>
			</div>
		</div>
		<div id="border">
			<div id="principal">
				<div id="margin">
					<h2><fmt:message key="country.framing.inactive" bundle="${i18n_eng}"/></h2>
					<br/>
				</div>
			</div>
		</div>
	</div>
</body>
<jsp:include page="content-security-header-deactivated.jsp"/>
<script type="text/javascript" src="js/autocompleteOff.js"></script>