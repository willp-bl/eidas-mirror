<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<fmt:setBundle basename="eu.stork.peps.package" var="i18n_eng"/>
<%@ taglib prefix="e" uri="https://www.owasp.org/index.php/OWASP_Java_Encoder_Project" %>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>
<% /* Page displayed when going back from IDP-AP, after user's consent, will redirect to S-PEPS.ColleagueResponse */%>

<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <meta http-equiv='pragma' content='no-cache'/>
    <meta http-equiv='cache-control' content='no-cache, no-store, must-revalidate'/>
	<meta http-equiv="Expires" content="-1"/>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
    <title><fmt:message key="stork.title" bundle="${i18n_eng}"/></title>
    <link href="resources/css/stylesheet.css" rel="stylesheet" type="text/css"/>
</head>

<body>
<jsp:include page="content-security-header-deactivated.jsp"/>

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
                <h2>
				<c:if test="${eidasAttributes}">
                    <fmt:message key="SpecificAPResponseEidas.text" bundle="${i18n_eng}">
                        <fmt:param value="${e:forHtml(spId)}"/>
                        <fmt:param value="${e:forHtml(LoA)}"/>
                    </fmt:message>
				</c:if>
				<c:if test="${!eidasAttributes}">
                    <fmt:message key="SpecificAPResponse.text" bundle="${i18n_eng}">
                        <fmt:param value="${e:forHtml(spId)}"/>
                        <fmt:param value="${e:forHtml(qaaLevel)}"/>
                    </fmt:message>
				</c:if>
                </h2>
                <br/>
                <span id="formContainer">
                    <form id="consentSelector" name="consentSelector" method="post" action="${e:forHtml(redirectUrl)}">
                        <table class="tabla" cellpadding="5" cellspacing="1">
                            <thead>
                                <tr>
                                    <td align="right" valign="top"></td>
                                    <td align="center"><fmt:message key="attribute.name" bundle="${i18n_eng}"/></td>
                                    <td align="center"><fmt:message key="attribute.value" bundle="${i18n_eng}"/></td>
                                </tr>
                            </thead>
                            <tbody>
                            <tr>
                                <td><h4><fmt:message key="attribute.mandatory" bundle="${i18n_eng}"/></h4></td>
                                <td align="right" valign="top"></td>
                                <td align="right" valign="top"></td>
                            </tr>
							<c:if test="${eidasAttributes}">
								<c:set var="categoryIsDisplayed" value="false"/>
								<c:forEach items="${pal}" var="palItem">
									<c:if test="${palItem.required && !fn:startsWith(fn:toLowerCase(displayAttr), 'false') && palItem.eidasNaturalPersonAttr}">
										<c:if test="${categoryIsDisplayed=='false'}">
											<tr>
												<td></td>
												<td align="center" valign="top"><h5><fmt:message key="attribute.naturalperson" bundle="${i18n_eng}"/></h5></td>
												<td></td>
											</tr>
											<c:set var="categoryIsDisplayed" value="true"/>
										</c:if>
										<tr>
											<td></td>
											<td align="left"><fmt:message key="${palItem.name}" bundle="${i18n_eng}"/></td>
											<td>
												<c:if test="${not empty palItem.value[0]}">
													${e:forHtml(palItem.value)}
												</c:if>
												<c:if test="${empty palItem.value[0]}">
													<table>
														<c:forEach items="${palItem.complexValue}" var="complexValue">
															<tr>
																<td align="left"><i>${e:forHtml(complexValue.key)}</i>:&nbsp;</td>
																<td align="center">${e:forHtml(complexValue.value)}</td>
															</tr>
														</c:forEach>
													</table>
												</c:if>
											</td>
										</tr>
									</c:if>
								</c:forEach>
								<c:set var="categoryIsDisplayed" value="false"/>
								<c:forEach items="${pal}" var="palItem">
									<c:if test="${palItem.required && !fn:startsWith(fn:toLowerCase(displayAttr), 'false') && palItem.eidasLegalPersonAttr}">
										<c:if test="${categoryIsDisplayed=='false'}">
											<tr>
												<td></td>
												<td align="center" valign="top"><h5><fmt:message key="attribute.legalperson" bundle="${i18n_eng}"/></h5></td>
												<td></td>
											</tr>
											<c:set var="categoryIsDisplayed" value="true"/>
										</c:if>
										<tr>
											<td></td>
											<td align="left"><fmt:message key="${palItem.name}" bundle="${i18n_eng}"/></td>
											<td>
												<c:if test="${not empty palItem.value[0]}">
													${e:forHtml(palItem.value)}
												</c:if>
												<c:if test="${empty palItem.value[0]}">
													<table>
														<c:forEach items="${palItem.complexValue}" var="complexValue">
															<tr>
																<td align="left"><i>${e:forHtml(complexValue.key)}</i>:&nbsp;</td>
																<td align="center">${e:forHtml(complexValue.value)}</td>
															</tr>
														</c:forEach>
													</table>
												</c:if>
											</td>
										</tr>
									</c:if>
								</c:forEach>
							</c:if>
							<c:if test="${!eidasAttributes}">
								<c:forEach items="${pal}" var="palItem">
									<fmt:message var="displayAttr" key="${palItem.name}.display" bundle="${i18n_eng}"/>
									<c:if test="${palItem.required && !fn:startsWith(fn:toLowerCase(displayAttr), 'false')}">
										<tr>
											<td></td>
											<td align="left"><fmt:message key="${palItem.name}" bundle="${i18n_eng}"/></td>
											<td>
												<c:if test="${not empty palItem.value[0]}">
													${e:forHtml(palItem.value)}
												</c:if>
												<c:if test="${empty palItem.value[0]}">
													<table>
														<c:forEach items="${palItem.complexValue}" var="complexValue">
															<tr>
																<td align="left"><i>${e:forHtml(complexValue.key)}</i>:&nbsp;</td>
																<td align="center">${e:forHtml(complexValue.value)}</td>
															</tr>
														</c:forEach>
													</table>
												</c:if>
											</td>
										</tr>
									</c:if>
								</c:forEach>
							</c:if>
                            <tr>
                                <td>
                                    <h4><fmt:message key="attribute.optional" bundle="${i18n_eng}"/></h4>
                                </td>
                                <td align="right" valign="top"></td>
                                <td align="right" valign="top"></td>
                            </tr>
							<c:if test="${eidasAttributes}">
								<c:set var="categoryIsDisplayed" value="false"/>
								<c:forEach items="${pal}" var="palItem">
									<c:if test="${!palItem.required && !fn:startsWith(fn:toLowerCase(displayAttr), 'false') && palItem.eidasNaturalPersonAttr}">
										<c:if test="${categoryIsDisplayed=='false'}">
											<tr>
												<td></td>
												<td align="center" valign="top"><h5><fmt:message key="attribute.naturalperson" bundle="${i18n_eng}"/></h5></td>
												<td></td>
											</tr>
											<c:set var="categoryIsDisplayed" value="true"/>
										</c:if>
										<tr>
											<td></td>
											<td align="left"><fmt:message key="${palItem.name}" bundle="${i18n_eng}"/></td>
											<td>
												<c:if test="${not empty palItem.value[0]}">
													${e:forHtml(palItem.value)}
												</c:if>
												<c:if test="${empty palItem.value[0]}">
													<table>
														<c:forEach items="${palItem.complexValue}" var="complexValue">
															<tr>
																<td align="left"><i>${e:forHtml(complexValue.key)}</i>:&nbsp;</td>
																<td align="center">${e:forHtml(complexValue.value)}</td>
															</tr>
														</c:forEach>
													</table>
												</c:if>
											</td>
										</tr>
									</c:if>
								</c:forEach>
								<c:set var="categoryIsDisplayed" value="false"/>
								<c:forEach items="${pal}" var="palItem">
									<c:if test="${!palItem.required && !fn:startsWith(fn:toLowerCase(displayAttr), 'false') && palItem.eidasLegalPersonAttr}">
										<c:if test="${categoryIsDisplayed=='false'}">
											<tr>
												<td></td>
												<td align="center" valign="top"><h5><fmt:message key="attribute.legalperson" bundle="${i18n_eng}"/></h5></td>
												<td></td>
											</tr>
											<c:set var="categoryIsDisplayed" value="true"/>
										</c:if>
										<tr>
											<td></td>
											<td align="left"><fmt:message key="${palItem.name}" bundle="${i18n_eng}"/></td>
											<td>
												<c:if test="${not empty palItem.value[0]}">
													${e:forHtml(palItem.value)}
												</c:if>
												<c:if test="${empty palItem.value[0]}">
													<table>
														<c:forEach items="${palItem.complexValue}" var="complexValue">
															<tr>
																<td align="left"><i>${e:forHtml(complexValue.key)}</i>:&nbsp;</td>
																<td align="center">${e:forHtml(complexValue.value)}</td>
															</tr>
														</c:forEach>
													</table>
												</c:if>
											</td>
										</tr>
									</c:if>
								</c:forEach>
							</c:if>
							<c:if test="${!eidasAttributes}">
								<c:forEach items="${pal}" var="palItem">
									<fmt:message var="displayAttr" key="${palItem.name}.display" bundle="${i18n_eng}"/>
									<c:if test="${!palItem.required && !fn:startsWith(fn:toLowerCase(displayAttr), 'false')}">
										<tr>
											<td></td>
											<td align="left"><fmt:message key="${palItem.name}" bundle="${i18n_eng}"/></td>
											<td>
												<c:if test="${not empty palItem.value[0]}">
													${e:forHtml(palItem.value)}
												</c:if>
												<c:if test="${empty palItem.value[0]}">
													<table>
														<c:forEach items="${palItem.complexValue}" var="complexValue">
															<tr>
																<td align="left"><i>${e:forHtml(complexValue.key)}</i>:&nbsp;</td>
																<td align="center">${e:forHtml(complexValue.value)}</td>
															</tr>
														</c:forEach>
													</table>
												</c:if>
											</td>
										</tr>
									</c:if>
								</c:forEach>
							</c:if>
                            </tbody>
                        </table>
                        <br/>
                        <input type="hidden" id="SAMLResponse" name="SAMLResponse" value="${e:forHtml(samlToken)}"/>
                        <input type="hidden" id="relayState" name="RelayState" value="${e:forHtml(RelayState)}"/>
                    </form>
                    <form id="cancelForm" name="cancelForm" method="post" action="${e:forHtml(redirectUrl)}">
                        <input type="hidden" id="SAMLResponse" name="SAMLResponse" value="${e:forHtml(samlTokenFail)}"/>
                        <c:if test="RelayState!=null">
                            <input type="hidden" id="relayState" name="RelayState" value="${e:forHtml(RelayState)}"/>
                        </c:if>
                    </form>
                </span><br/><br/>
                <div id="buttonBar" class="cancelButton">
                    <button type="button" id="buttonBar.send">Send</button>
                    <button type="button" id="buttonBar.cancel">Cancel</button>
                </div>
                <div id="buttons"></div>
            </div>
        </div>
    </div>
</div>
<script type="text/javascript" src="js/autocompleteOff.js"></script>
<script type="text/javascript" src="js/redirectConsent.js"></script>
</body>
</html>
