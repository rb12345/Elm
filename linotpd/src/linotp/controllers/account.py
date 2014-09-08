# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2014 LSE Leading Security Experts GmbH
#
#    This file is part of LinOTP server.
#
#    This program is free software: you can redistribute it and/or
#    modify it under the terms of the GNU Affero General Public
#    License, version 3, as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the
#               GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#

"""
account controller - used for loggin in to the selfservice
"""


import traceback

from pylons import request, response, tmpl_context as c
from pylons.controllers.util import abort, redirect

from linotp.lib.base import BaseController
from pylons.templating import render_mako as render

from linotp.lib.reply   import sendError
from linotp.model.meta  import Session

from linotp.lib.util    import get_version
from linotp.lib.util    import get_copyright_info

from linotp.lib.realm    import getRealms
from linotp.lib.realm    import getDefaultRealm
from linotp.lib.user     import getRealmBox



import logging
import webob


log = logging.getLogger(__name__)


optional = True
required = False

# The HTTP status code, that determines that
# the Login to the selfservice portal is required.
# Is also defined in selfservice.js
LOGIN_CODE = 576

class AccountController(BaseController):
    '''
    The AccountController
        /account/
    is responsible for authenticating the users for the selfservice portal.
    It has the following functions:
        /account/login
        /account/dologin
    '''


    def __before__(self, action, **params):

        log.debug("[__before__::%r] %r" % (action, params))

        try:
            self.set_language()
            c.version = get_version()
            c.licenseinfo = get_copyright_info()

        except webob.exc.HTTPUnauthorized as acc:
            ## the exception, when an abort() is called if forwarded
            log.error("[__before__::%r] webob.exception %r" % (action, acc))
            log.error("[__before__] %s" % traceback.format_exc())
            Session.rollback()
            Session.close()
            raise acc

        except Exception as exx:
            log.error("[__before__::%r] exception %r" % (action, exx))
            log.error("[__before__] %s" % traceback.format_exc())
            Session.rollback()
            Session.close()
            return sendError(response, exx, context='before')

        finally:
            log.debug("[__before__::%r] done" % (action))

    def login(self):
        log.debug("[login] selfservice login screen")
        identity = request.environ.get('REMOTE_USER')
        if identity is not None:
            # After login We always redirect to the start page
            redirect("/selfservice")

        Session.close()


    def logout(self):
        identity = request.environ.get('REMOTE_USER')
        if identity is None:
            # After logout We always redirect to the start page
            redirect("/")

        http_host = request.environ.get("HTTP_HOST")
        url_scheme = request.environ.get("wsgi.url_scheme")
        redirect("%s://%s/elm/logout" % (url_scheme, http_host))
        #redirect('https://webauth.ox.ac.uk/logout')

        Session.close()


#eof##########################################################################