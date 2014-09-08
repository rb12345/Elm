# -*- coding: utf-8 -*-
<!--
 *
 *   LinOTP - the open source solution for two factor authentication
 *   Copyright (C) 2010 - 2014 LSE Leading Security Experts GmbH
 *
 *   This file is part of LinOTP server.
 *
 *   This program is free software: you can redistribute it and/or
 *   modify it under the terms of the GNU Affero General Public
 *   License, version 3, as published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU Affero General Public License for more details.
 *
 *   You should have received a copy of the
 *              GNU Affero General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 *    E-mail: linotp@lsexperts.de
 *    Contact: www.linotp.org
 *    Support: www.lsexperts.de
 *
-->
<h1>${_("Provision your Google Authenticator")}</h1>

<div id='googletokenform'>
	<form class="cmxform" name='myForm'> 
		<fieldset>
		<p>
		${_("1. First,  install the Google Authenticator application on your Android or iOS device.")}
		<ul>
		<li><a href='https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2' target='extern'>${_("Android")}</a></li>
		<li><a href='http://itunes.apple.com/uk/app/google-authenticator/id388497605?mt=8' target='extern'>${_("iOS")}</a><br>
			${_("If you are using an iOS device, you can scan the following QR code instead.")}     
		     <span id=qr_code_iphone_download></span>
			</li>
		</ul>
		<p>${_("2. Select a token type:")}<br>
			<label for=google_type>Token:</label> 
			<select id=google_type>
				% if 'webprovisionGOOGLE' in c.actions:
				<option value=hotp>${_("event based (HOTP)")}</option>
				%endif
				% if 'webprovisionGOOGLEtime' in c.actions:
				<option value=totp>${_("time based (TOTP)")}</option>
				%endif
			</select>
		<button class='action-button' id='button_provisionGoogle' onclick="provisionGoogle(); return false;">
			${_("enroll Google Authenticator")}
		</button>
		</p>
		<div id="provisionGoogleResultDiv">
			<p>${_("3.")} <b>${_("Google Authenticator")}</b> ${_("successfully created!")}</p>
			<p>${_("If you are viewing this site on the same device as your Google Authenticator app, click the link below to activate your code:")}
				 <a id=google_link>${_("Activate key")}</a>
			</p>
			<p>${_("Alternatively, scan the QR code below with your authenticator device.")}</p>
			<p><span id=google_qr_code></span></p>
		</div>
		</fieldset>
	</form>
</div>

<script>
	   	$('#provisionGoogleResultDiv').hide();
	   	$('#qr_code_iphone_download').show();
	   	$('#qr_code_iphone_download').html(generate_qrcode(10,"http://itunes.apple.com/uk/app/google-authenticator/id388497605?mt=8"));
</script>
