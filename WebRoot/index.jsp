<!-- "$Id: index.jsp 3180 2008-07-21 11:48:20Z jre $"; -->
<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<meta http-equiv="Expires" content="0" />
<title>OIOSAML.java</title>
<style type="text/css">
body {
	background-color: white;
	margin: 20px;
}
body, tr, td {
	font-family: Verdana, Helvetica, sans-serif;
	color: #456974;
}
div#pagecontainer {
	width: 80%;
}
h1, h2, h3, h4 {
	color: #76c2bc;
	border-bottom: 1px solid #76c2bc;
}
.monospace {
	font-family: monospace;
}
legend {
	font-weight: bold;
}
fieldset {
	margin-top: 10px;
	margin-bottom: 10px;
}
span.emphasis {
	font-weight: bold;
}
</style>
</head>
<body>
	<%@page import="dk.itst.oiosaml.configuration.SAMLConfigurationFactory"%>
	<%@page import="dk.itst.oiosaml.configuration.FileConfiguration" %>

    <h1>OIOSAML.java</h1>

	<%
		try {
			SAMLConfigurationFactory.getConfiguration().getSystemConfiguration();
			String homeDir = ((FileConfiguration) SAMLConfigurationFactory.getConfiguration()).getHomeDir();
	%>
	
	<h2>Your aplication is already configured</h2>
	
	<p>oiosaml-j.home points to <%=homeDir %>, which either does not exist or is not empty. This means that the configuration cannot proceed.
	If you really want to configure, remove all files from <%=homeDir %> or create it if it does not exist.</p>

	<%
		} catch (RuntimeException e) {
	%>
	<h2>System is not configured</h2>
	<a href="saml/configure">Configure the system here</a>.
	<%
		}
	%>
	
	<br />

	<div style="text-align: center; float: left">
		<img src="oiosaml.gif" alt="oiosaml.java" />
	</div>
</body>
</html>