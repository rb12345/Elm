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
<h1>${_("Delete Token")}</h1>

<div id='deleteform'>
	<form class="cmxform" name='myForm'>
		<fieldset>
			<span id=del_error>There was an error deleting your token. Please refresh the page and try again.</span>
			<span id=del_success>Your token has been deleted. If this was your last token, the Single Sign On service will no longer ask for an access code when you login. You will also be unable to access secure resources that require two-factor authentication: to retain access to these services, you should create a new token.</span>

			<p>This page allows you to delete a token. Your authenticator app will continue to generate codes, but they will no longer be accepted by the Single Sign On service.</p>
			<p>If all of your tokens are deleted, the Single Sign On service will no longer ask for an access code when you login. You will also be unable to access secure resources that require two-factor authentication: to retain access to these services, you should create a new token.</p>
			<table>
				<tr>
					<!--[if lte IE 9]>
						<td><label class="ie-label" for="selectedToken">Token</label></td>
					<![endif]-->
					<td><input id="selectedToken" type='text' class='selectedToken' class="text ui-widget-content ui-corner-all" disabled value='' placeholder="Token"/>
					<td><span class="form-help">Click a token on the left to select it.</span></td>
				</tr>
			</table>
			<button class='action-button' id='button_delete' onclick="token_delete(); return false;">${_("Delete Token")}</button>
		</fieldset>
	</form>
</div>

<script>
		// Initial display.
	   	$('#del_success').hide();
		$('#del_error').hide();
</script>
