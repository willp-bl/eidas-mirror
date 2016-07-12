<!DOCTYPE html>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<fmt:setBundle basename="eu.eidas.node.package" var="i18n_eng"/>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>
<%@ taglib prefix="e" uri="https://www.owasp.org/index.php/OWASP_Java_Encoder_Project" %>
<%@ taglib prefix="token" uri="https://eidas.europa.eu/" %>

<html lang="en">

<head>
    <jsp:include page="htmlHead.jsp"/>
    <title><fmt:message key="consent.page.title" bundle="${i18n_eng}"/></title>
</head>
<body>
<main>
    <div class="wrapper">
        <jsp:include page="centralSliderNoAnim.jsp"/>
        <jsp:include page="leftColumnNoAnim.jsp"/>
        <div class="col-right">
            <div class="col-right-inner">
                <div class="clearfix">
                    <div class="menu-top"> <a class="item text-minus" href="#"></a> <a class="item text-plus" href="#"></a> <a class="item contrast" href="#"></a> </div>
                </div>
                <div class="col-right-content">
                    <jsp:include page="content-security-header-deactivated.jsp"/>
                    <h1 class="title">
                        <fmt:message key="eidas.title" bundle="${i18n_eng}"/>
                        <span class="text-error"><fmt:message key="Service.error.title" bundle="${i18n_eng}"/></span>
                    </h1>
                    <c:if test="${!empty exception}">
                        <p class="text-center">${exception.errorMessage}</p>
                    </c:if>
                    <c:if test="${(!empty exception.samlTokenFail)}">
                        <form action="${e:forHtml(errorRedirectUrl)}" name="redirectForm" id="redirectForm" method="post">
                            <input type="hidden" name="SAMLResponse" id="SAMLResponse" value="${e:forHtml(exception.samlTokenFail)}" />
                            <input type="hidden" name="errorMessage" id="errorMessage" value="${e:forHtml(exception.errorMessage)}" />
							<c:if test="${!empty errorRedirectUrl}">
								<input type="submit" id="redirectForm_sendButton" name="sendButton" value="send" />
							</c:if>
                        </form>
                    </c:if>
                    <h2 class="sub-title text-highlight"><fmt:message key="eidas.cooperation" bundle="${i18n_eng}" /></h2>
                </div>
                <jsp:include page="footer-img.jsp"/>
            </div>
        </div>
    </div>
</main>
<jsp:include page="footerScripts.jsp"/>
<script type="text/javascript" src="js/autocompleteOff.js"></script>
<!--script type="text/javascript" src="js/redirectOnload.js"></script-->
</body>
</html>