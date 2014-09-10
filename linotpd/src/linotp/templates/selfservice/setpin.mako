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
<h1>${_("Change Token PIN")}</h1>

<div id='passwordform'>
	<form class="cmxform" name='myForm'>
		<fieldset>
			<span id=error></span>
			<span id=success>Your PIN was updated successfully.</span>

			<p>This page allows you to change the PIN associated with a token. Once you update your PIN, you should use the new PIN when logging in to Single Sign On services.</p>
			<p>Note that the PIN for each token is independent. If you have multiple tokens, this page will only update the PIN for the selected token - you should repeat the process for your other tokens if you wish to change their PINs as well.</p>
			<table>
				<tr>
					<!--[if lte IE 9]>
						<td><label class="ie-label" for="selectedToken">Token</label></td>
					<![endif]-->
					<td><input id="selectedToken" type='text' class='selectedToken' class="text ui-widget-content ui-corner-all" disabled value='' placeholder="Token"/>
					<td><span class="form-help">Click a token on the left to select it.</span></td>
				</tr>
				<tr>
					<!--[if lte IE 9]>
						<td><label class="ie-label" for="pin1">New PIN</label></td>
					<![endif]-->
					<td><input autocomplete="off" type='password' id="pin1" class="text ui-widget-content ui-corner-all" value='' placeholder="New PIN"/></td>
				</tr>
				<tr>
					<!--[if lte IE 9]>
						<td><label class="ie-label" for="pin1">Confirm new PIN</label></td>
					<![endif]-->

					<td><input autocomplete="off" type='password' onkeyup="checkpins('pin1', 'pin2');" id="pin2" class="text ui-widget-content ui-corner-all" value='' placeholder="Confirm new PIN"/></td>
				</tr>
			</table>
			<button class='action-button' id='button_setpin' onclick="setpin(); return false;">${_("set PIN")}</button>

		</fieldset>
	</form>
</div>

<script>
		// Initial display.
	   	$('#success').hide();
		$('#error').hide();
</script>