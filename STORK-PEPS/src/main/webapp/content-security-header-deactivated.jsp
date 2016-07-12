<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<fmt:setBundle basename="eu.stork.peps.package" var="i18n_eng"/>
<%/**
 * This message is displayed to the user when the CSP is not active, the content-security-policy directive when supported will indicates the browser to not execute
 * embedded javascript.
 */%>
<div id="cspMessage" class="warningCsp"></div>

<script type="text/javascript" src="js/testCSP.js"></script>