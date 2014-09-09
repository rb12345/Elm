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
			<table>
				<tr>
					<!--[if lte IE 9]>
						<td><label class="ie-label" for="selectedToken">Token</label></td>
					<![endif]-->
					<td><input id="selectedToken" type='text' class='selectedToken' class="text ui-widget-content ui-corner-all" disabled value='' placeholder="Token"/>
					<td><p>Click a token on the left to select it.</p></td>
				</tr>
				<tr>
					<!--[if lte IE 9]>
						<td><label class="ie-label" for="pin1">New PIN</label></td>
					<![endif]-->
					<td><input autocomplete="off" type='password' id='pin1' class="text ui-widget-content ui-corner-all" value='' placeholder="New PIN"/></td>
				</tr>
				<tr>
					<!--[if lte IE 9]>
						<td><label class="ie-label" for="pin1">Confirm new PIN</label></td>
					<![endif]-->

					<td><input autocomplete="off" type='password' onkeyup="checkpins('pin1', 'pin2');" id='pin2' class="text ui-widget-content ui-corner-all" value='' placeholder="Confirm new PIN"/></td>
				</tr>
			</table>
			<button class='action-button' id='button_setpin' onclick="setpin(); return false;">${_("set PIN")}</button>
			<input type='hidden' value='${_("The passwords do not match!")}' 		id='setpin_fail'/>
			<input type='hidden' value='${_("Error setting PIN: ")}' 			id='setpin_error'/>
			<input type='hidden' value='${_("PIN set successfully")}'			id='setpin_ok'/>
		</fieldset>
	</form>
</div>
