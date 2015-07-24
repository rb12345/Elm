# -*- coding: utf-8 -*-

#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2014 LSE Leading Security Experts GmbH
#
#    This file is part of LinOTP userid resolvers.
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

# This module communicates with Oxford University's Oak LDAP service
# to identify users.
# Dependencies: UserIdResolver

from useridresolver.UserIdResolver import UserIdResolver
from useridresolver.UserIdResolver import getResolverClass

import ldap
import ldap.sasl
import ldap.filter

import sys
import traceback
import binascii
from hashlib import sha1
import tempfile

from datetime import datetime
if sys.version_info[0:2] >= (2, 6):
    from json import loads
else:
    from simplejson import loads
import logging

import os

# Path to the Oak LDAP credential file.
os.environ["KRB5CCNAME"] = "/etc/krb5/oak-ldap.mfa.it.ox.ac.uk.ccache"

log = logging.getLogger(__name__)

ENCODING = 'utf-8'
DEFAULT_SIZELIMIT = 1000
BIND_NOT_POSSIBLE_TIMEOUT = 30


class IdResolver (UserIdResolver):
    '''
    LDAP User Id resolver
    '''

    nameDict = {}
    conf = ""

    fields = {
        "username": 1,
        "userid": 1,
        "description": 0,
        "phone": 0,
        "mobile": 0,
        "email": 0,
        "givenname": 0,
        "surname": 0,
        "gender": 0
    }

    searchFields = {
        "username": "text",
        "userid": "text",
        "email": "text",
        "givenname": "text",
        "surname": "text"
    }

    @classmethod
    def setup(cls, config=None, cache_dir=None):
        log.info("[setup] Setting up the OakResolver")
        return

    # The mapping of these search fields to the ldap attributes it
    # stored in self.userinfo

    @classmethod
    def testconnection(self, params):
        '''
        This is used to test if the given parameter set will do a successful
        LDAP connection.
        params are:
            OAKREALM
            SIZELIMIT
        '''

        try:
            # do a bind
            uri = 'ldap://ldap.oak.ox.ac.uk:389'
            base = "ou=people,dc=oak,dc=ox,dc=ac,dc=uk"

            auth = ldap.sasl.gssapi("")
            l = ldap.initialize(uri)

            l.network_timeout = 10.0

            l.start_tls_s()
            l.sasl_interactive_bind_s("",auth)

            # We use eduPersonOrgUnitDN's oakUnitCode attribute to identify user realms.
            #realmfilter = "(eduPersonOrgUnitDN=oakUnitCode=%s,ou=units,dc=oak,dc=ox,dc=ac,dc=uk)" % params['OAKREALM']
            realmfilter = ""

            # We use the oakOxfordSSOUsername as the user name.
            #searchfilter = "(&(oakOxfordSSOUsername=*)%s)" % realmfilter
            searchfilter = "(oakOxfordSSOUsername=*)"

            results = 0;
            sizelimit = int(DEFAULT_SIZELIMIT)
            try:
                sizelimit = int(params.get("SIZELIMIT"))
            except:
                pass

            # Do the actual LDAP query.
            ldap_result_id = l.search_ext(base,
                                          ldap.SCOPE_SUBTREE,
                                          filterstr=searchfilter,
                                          sizelimit=sizelimit)
                                          
            # Loop through the results and count them.
            while 1:
                result_type, result_data = l.result(ldap_result_id, 0)
                if (result_data == []):
                    break
                else:
                    if result_type == ldap.RES_SEARCH_ENTRY:
                        results += 1

            # unbind
            l.unbind_s()
        except ldap.LDAPError as  e:
            log.error("[testconnection] LDAP Error: %s\n%s"
                                            % (str(e), traceback.format_exc()))
            return ("error", str(e))

        return ("success", results)

    def __init__(self):
        """ Initialize the ldap resolver class
        """
        self.realm = ""
        self.loginnameattribute = "oakOxfordSSOUsername"

        self.ldapuri = "ldaps://ldap.oak.ox.ac.uk"
        self.base = "ou=people,dc=oak,dc=ox,dc=ac,dc=uk"
        self.filter = ""
        self.searchfilter = ""
        self.realmfilter = ""

        # What values do we get from Oak, and what internal labels do we map them to?
        self.userinfo = {
            "username": "oakOxfordSSOUsername",
            "email" : "mail",
            "surname" : "sn",
            "givenname" : "givenName"
        }
        
        self.timeout = 10
        self.bind_not_possible = False
        self.bind_not_possible_time = datetime.now()
        self.sizelimit = 5
        self.l_obj = None

    def close(self):
        """
        end and unbind an LDAP connection
        """

        try:
            if self.l_obj is not None:
                self.l_obj.unbind_s()

        except ldap.LDAPError as  error:
            log.error("[unbind] LDAP error: %r" % error)
        finally:
            self.l_obj = None

    def bind(self):
        """
        bind() - this function starts an LDAP connection
        """

        if self.l_obj is not None:
            return self.l_obj

        if self.bind_not_possible:
            t2 = datetime.now()
            tdelta = t2 - self.bind_not_possible_time
            # If we try a bind within 30 seconds, we will
            # bail out!
            if tdelta.seconds > BIND_NOT_POSSIBLE_TIMEOUT or tdelta.days > 1:
                log.info("[bind] Resetting the bind_not_possible timeout.")
                self.bind_not_possible = False
            else:
                log.error("[bind] Previous LDAP bind attempt timed out. Please wait %r seconds before retrying." % (BIND_NOT_POSSIBLE_TIMEOUT - tdelta.seconds))
                return False

        uri = self.ldapuri
        log.debug("[bind] trying to bind to server: %r" % uri)
        l_obj = None

        try:
            # Connect and bind.
            log.debug("[bind] LDAP: Try to bind to %r", uri)
            auth = ldap.sasl.gssapi("")
            l_obj = ldap.initialize(uri, trace_level=0)

            l_obj.network_timeout = self.timeout

            #l_obj.start_tls_s()
            l_obj.sasl_interactive_bind_s("",auth)

            self.l_obj = l_obj
            log.debug("[bind] Successfully bound to %r", uri)
            return l_obj
        except ldap.LDAPError as  e:
            log.error("[bind] LDAP error: %r" % e)
            log.error("[bind] LDAPURI   : %r" % uri)
            log.error("[bind] %s" % traceback.format_exc())

        # We were not able to do a successful bind! :-(
        self.bind_not_possible = True
        self.bind_not_possible_time = datetime.now()
        self.l_obj = l_obj
        return l_obj

    def getUserId(self, loginname):
        '''
        return the userId which mappes to an loginname

        :param loginName: login name of the user
        :type loginName:  string

        :return: userid - unique idenitfier for this unser
        :rtype:  string
        '''

        userid = ''

        log.debug("[getUserId] resolving userid for %r: %r" % (type(loginname), loginname))

        if type(loginname) == unicode:
            ## we're being called externally with an unicode string
            LoginName = loginname.encode(ENCODING)

        elif type(loginname) == str:
            ## we're being called internally with a UTF-8 string
            LoginName = loginname

        else:
            log.error("[getUserId] Unsupported type of loginname (%r): %s" % (loginname, type(loginname)))
            return userid

        if len(loginname) == 0:
            return userid

        log.debug("[getUserId] type of LoginName %s" % type(LoginName))

        #fil = self.filter % LoginName.decode(ENCODING)
        fil = ldap.filter.filter_format(self.filter, [LoginName.decode(ENCODING)])
        fil = fil.encode(ENCODING)
        l_obj = self.bind()

        if not l_obj:
            return userid

        # We base the user ID off the oakPrimaryPersonID field.
        attrlist = []
        attrlist.append("oakPrimaryPersonID")

        log.debug("[getUserId] filter string is %s" % fil)

        resultList = None
        try:
            l_id = l_obj.search_ext(self.base,
                              ldap.SCOPE_SUBTREE,
                              filterstr=fil,
                              sizelimit=self.sizelimit,
                              attrlist=attrlist)
            resultList = l_obj.result(l_id, all=1)[1]
        except ldap.LDAPError as exc:
            log.error("[getUserId] LDAP error: %r" % exc)
            resultList = None

        if resultList == None:
            log.debug("[getUserId] : empty result ")
            return userid
            
        # [0][0] is the distinguished name

        res = None

        if len(resultList) == 0:
            log.debug("[getUserId] resultList is empty")
        else:
            res = resultList[0][1]
            if res != None:
                for key in res:
                   if key.lower() == "oakPrimaryPersonID".lower():
                        userid = res.get(key)[0]

        if res == None or userid == '':
            log.debug("[getUserId] : empty result for  %r" % (loginname))
        else:
            # Calculate the user ID using a SHA-1 hash of the oakPrimaryPersonId parameter.
            log.debug("[getUserId] userid: %r:%r" % (type(userid), userid))
            uname_hash = sha1(userid.encode("utf-8")).digest()
            log.debug(binascii.hexlify(uname_hash))

        return userid

    def getUsername(self, userid):
        '''
        get the loginname from the given userid

        :param userId: userid descriptor
        :type userId: string

        :return: loginname
        :rtype:  string
        '''

        log.debug("[getUsername]")

        username = u''

        ## getUserLDAPInfo returns (now) a list of unicode values
        l_user = self.getUserLDAPInfo(userid)

        if self.loginnameattribute in l_user:
            username = l_user[self.loginnameattribute]
        return username

    def getUserLDAPInfo(self, userid):
        """
        getUserLDAPInfo(UserId)

        This function returns all user information for a given user object
        identified by UserID. In LDAP case this is the oakPrimaryPersonID

        :param userid: user identifier (in unicode)
        :type  userid: unicode or str

        :return: user info dict
        :rtype: dict

        """
        log.debug("[getUserLDAPInfo]")

        # change unicode to utf-8 str
        UserId = userid.encode(ENCODING)

        resultList = {}

        l_id = 0
        l_obj = self.bind()

        if l_obj:
            try:
                # Search by oakPrimaryPersonID
                filterstr = "(%s=%s)" % ("oakPrimaryPersonID", UserId)
                l_id = l_obj.search_ext(self.base,
                                      ldap.SCOPE_SUBTREE,
                                      filterstr=filterstr,
                                      sizelimit=self.sizelimit)

                r = l_obj.result(l_id, all=1)[1]

                if r:
                    resList = r[0][1]
                    resList["dn"] = [r[0][0]]

                    resultList = {}

                    ## now convert the resList to unicode:
                    ##   dict of list(UTF-8)
                    for key in resList:
                        val = resList.get(key)
                        rval = val

                        if type(val) == list:
                            ## val should be a list of utf str
                            rval = []
                            for v in val:
                                try:
                                    if type(v) == str:
                                        rval.append(v.decode(ENCODING))
                                    else:
                                        rval.append(v)
                                except:
                                    rval.append(v)
                                    log.debug('[getUserLDAPInfo] failed to '
                                              'decode data type %r: %r'
                                                                % (type(v), v))

                        elif type(val) == str:
                            ## or val might be a direct utf-8 str
                            try:
                                rval = val.decode(ENCODING)
                            except:
                                rval = val
                                log.debug('[getUserLDAPInfo] failed to decode '
                                          'data type %r: %r'
                                          % (type(val), val))
                        else:
                            ## this should not be reached -
                            ## so anything different is treated as unknown
                            rval = val
                            log.warning('[getUserLDAPInfo] unknown and '
                                        'unsupported LDAP return data type'
                                        ' %r: %r' % (type(val), val))

                        resultList[key] = rval

            except ldap.LDAPError as  e:
                log.error("[getUserLDAPInfo] LDAP error: %s" % str(e))
                log.error("[getUserLDAPInfo] %s" % traceback.format_exc())

        return resultList

    def getUserInfo(self, userid):
        '''
        return all user related information

        :param userId: specied user
        :type userId:  string
        :return: dictionary, containing all user related info
        :rtype:  dict

        The return is a dictionary with well defined keys:
        fields = {
            "username":1, "userid":1,
            "description":0,
            "phone":0,"mobile":0,"email":0,
            "givenname":0,"surname":0,"gender":0
          }

        '''
        log.debug("[getUserInfo]")

        ret = {}

        user = self.getUserLDAPInfo(userid)

        if len(user) > 0:
            ret['userid'] = userid

            for f in self.userinfo:
                if self.userinfo[f] in user:
                    ret[f] = user[self.userinfo[f]][0]
                else:
                    ret[f] = ''

        return ret

    def getResolverId(self):
        '''
        getResolverId - provide the resolver identifier

        :return: returns the resolver identifier string or empty string
                    if not exist
        :rtype : string

        '''
        log.debug("[getResolverId]")
        resolver = u"OakIdResolver.IdResolver"
        if self.conf != "":
            resolver = resolver + "." + self.conf
        return resolver

    def getConfigEntry(self, config, key, conf, required=True, default=""):
        '''
        getConfigEntry - retrieve an entry from the config

        :param config: dict of all configs
        :type  config: dict
        :param key: key which is searched
        :type key: string
        :param conf: scope of the config eg. connect.sql
        :type conf: string
        :param required: if this value ist true and the key is not defined, an
                         exception sill be raised
        :type required:  boolean
        :param default: fallback value if confg has no such entry
        :type default: any

        :return: the value of the specified key
        :rtype:  value type - in most cases string ;-)

        '''
        log.debug("[getConfigEntry]")

        ckey = key
        cval = default
        config_found = False
        log.debug("[getConfigEntry] searching key %r in config %r"
                                                                % (key, conf))
        if conf != "" or None:
            ckey = ckey + "." + conf
            if ckey in config:
                config_found = True
                cval = config[ckey]

        if cval == "":
            if key in config:
                config_found = True
                cval = config[key]

        if required and not config_found:
            log.error("[getConfigEntry] missing config entry %s in config %s"
                                                                % (key, conf))
            self.brokenconfig = True
            self.brokenconfig_text = ("Broken Config: missing config entry "
                                            "%s in config %s" % (key, conf))
            raise Exception("missing config entry: %s in config %s"
                                                            % (key, config))

        return cval

    @classmethod
    def getResolverClassType(cls):
        return 'oakresolver'

    def getResolverType(self):
        '''
        getResolverType - return the type of the resolver

        :return: returns the string 'oakresolver'
        :rtype:  string
        '''
        return IdResolver.getResolverClassType()

    @classmethod
    def getResolverClassDescriptor(cls):
        '''
        return the descriptor of the resolver, which is
        - the class name and
        - the config description

        :return: resolver description dict
        :rtype:  dict
        '''

        log.debug("[getResolverDescriptor]")

        descriptor = {}
        typ = cls.getResolverClassType()
        descriptor['clazz'] = "useridresolver.OakIdResolver.IdResolver"
        descriptor['config'] = {
            'OAKREALM' : 'string',
            'SIZELIMIT' : 'int',
        }
        return {typ: descriptor}

    def getResolverDescriptor(self):
        return IdResolver.getResolverClassDescriptor()

    def loadConfig(self, config, conf=""):
        '''
        loadConfig - load the config for the resolver
            The calling applications passes the LDAP configuration:
            FILTER
            BASE

        :param config: configuration for the sqlresolver
        :type  config: dict
        :param conf: configuration postfix
        :type  conf: string
        '''

        log.debug("[loadConfig] Config:  %r" % config)
        log.debug("[loadConfig] Conf  :  %r" % conf)
        self.conf = conf

        self.realm = self.getConfigEntry(config, "linotp.oakresolver.OAKREALM", conf)

        sizelimit = self.getConfigEntry(config,
                                "linotp.oakresolver.SIZELIMIT", conf,
                                required=False, default=DEFAULT_SIZELIMIT)

        #self.sizelimit      = float(sizelimit)
        try:
            self.sizelimit = int(sizelimit)
        except ValueError:
            self.sizelimit = int(DEFAULT_SIZELIMIT)
        except TypeError:
            self.sizelimit = int(DEFAULT_SIZELIMIT)
        log.debug("[loadConfig: the sizelimit is: %s, %i"
                                                % (sizelimit, self.sizelimit))

        #self.realmfilter = "(eduPersonOrgUnitDN=oakUnitCode=%s,ou=units,dc=oak,dc=ox,dc=ac,dc=uk)" % self.realm
        self.realmfiler = ""

        self.filter = "(%s=%%s)" % (self.loginnameattribute)
        self.searchfilter = "(%s=*)" % (self.loginnameattribute)

        return self

    def getSearchFields(self, searchDict=None):
        '''
        return all fields on which a search could be made

        :return: dictionary of the search fields and their types - not used!!
        :rtype:  dict
        '''
        log.debug("[getSearchFields]")
        return self.searchFields

    def searchLDAPUserList(self, key, value):
        """
        finds the user objects, that have the term 'value' in the
                user object field 'key'

        :param key: The key may be an ldap attribute like 'loginname'
                      or 'email'.
        :type  key: string
        :param value: The value is a regular expression.
        :type value:string

        :return:  a list of dictionaries (each dictionary contains a
                    user object) or an empty string if no object is found.
        :rtype: list
        """

        log.debug("[searchLDAPUserList]")

        searchFilter = key + "=" + value
        resultList = []
        l_obj = self.bind()
        if l_obj:
            try:
                ldap_result_id = l_obj.search_ext(self.base,
                                                  ldap.SCOPE_SUBTREE,
                                                  filterstr=searchFilter,
                                                  sizelimit=self.sizelimit)
                while 1:
                    result_type, result_data = l_obj.result(ldap_result_id, 0)
                    if (result_data == []):
                        break
                    else:
                        if result_type == ldap.RES_SEARCH_ENTRY:
                            resultList.append(result_data)
            except ldap.LDAPError as exc:
                log.error("[searchLDAPUserList] LDAP error: %r" % exc)

            if resultList:
                return resultList
        return resultList

    def _getUserDN(self, uid):
        '''
        This function takes the UID and returns the DN of the user object
        '''
        DN = self.getUserLDAPInfo(uid).get("dn")[0]
        return DN

    def checkPass(self, uid, password):
        '''
        checkPass - checks the password for a given uid.

        :param uid: userid to be checked
        :type  uid: string
        :param password: user password
        :type  password: string

        :return :  true in case of success, false if password does not match
        :rtype :   boolean

        :attention: First the UID needs to be converted to the DN, in
                        case the Uid is not the DN
        '''

        ## Patch:
        ##   simple bind allows anonymous auth which raises no exception
        ##   so we return immediatly if no password is given
        ##

        log.debug("[checkPass]")

        if password == None or len(password) == 0:
            return False

        if type(password) == unicode:
            password = password.encode(ENCODING)

        if type(uid) == unicode:
            uid = uid.encode(ENCODING)

        DN = self._getUserDN(uid)

        if type(DN) == unicode:
            DN = DN.encode(ENCODING)

        log.debug("[checkPass] DN: %r" % DN)

        uri = self.ldapuri

        log.debug("[checkPass] we will try to authenticate to this LDAP "
                  "server: %r" % uri)

        l = None
        try:
            log.info("[checkPass] check password for user %r "
                     "on LDAP server %r" % (DN, uri))
            auth = ldap.sasl.gssapi("")
            l = ldap.initialize(uri, trace_level=0)

            l.network_timeout = self.timeout
            l.start_tls_s()
            l.sasl_interactive_bind_s("",auth)

            log.info("[checkPass] ldap bind for %r successful" % DN)
            return True

        except ldap.INVALID_CREDENTIALS as exc:
            log.warning("[checkPass] invalid credentials: %r" % exc)

        except ldap.LDAPError as  exc:
            log.warning("[checkPass] checking password failed: %r" % exc)

        finally:
            if l is not None:
                l.unbind_s()

        return False

    def guid2str(self, guid):
        '''
        convert the binary MS AD GUID to something that could be displayed
          http://support.microsoft.com/kb/325649

        :param guid: binary value
        :type  guid: binary

        :return: string representation of the guid
        :rtype:  string
        '''
        log.debug("[guid2str] converting MS AD GUID: %r" % guid)
        res = binascii.hexlify(guid)
        return res

    def getUserList(self, searchDict):
        '''
        retrieve a list of users

        :param searchDict: dictionary of the search criterias
        :type  searchDict: dict
        :return: resultList, a dict with user info
        '''

        try:
            searchFilter = u"(&"
            searchFilter = searchFilter + self.searchfilter
            log.debug("[getUserList] searchfilter: %r" % self.searchfilter)
            for skey, sval in searchDict.iteritems():
                log.debug("[getUserList] searchkeys: %r / %r" % (skey, sval))
                if skey in self.userinfo:
                    key = self.userinfo[skey]
                    value = searchDict[skey]
                    # value and searchFilter are Unicode!
                    searchFilter += u"(%s=%s)" % (key, value)
                else:
                    log.warning("[getUserList] Unknown searchkey: %r" % skey)
            searchFilter += ")"
            log.debug("[getUserList] searchfilter: %r" % searchFilter)
        except Exception as exep:
            log.error("[getUserList] Error creating searchFilter: %r" % exep)
            log.error("[getUserList] %s" % traceback.format_exc())

        resultList = []

        l_obj = self.bind()

        if l_obj:
            try:
                log.debug("[getUserList] doing search with filter %r"
                                                                % searchFilter)
                log.debug("[getUserList] type of searchfilter: %r"
                                                        % type(searchFilter))
                attrlist = []
                for ukey, uval in self.userinfo.iteritems():
                    attrlist.append(str(uval))

                attrlist.append("oakPrimaryPersonID")

                ldap_result_id = l_obj.search_ext(self.base,
                                      ldap.SCOPE_SUBTREE,
                                      filterstr=searchFilter.encode(ENCODING),
                                      sizelimit=self.sizelimit,
                                      attrlist=attrlist)

                while 1:
                    userdata = {}
                    result_type, result_data = l_obj.result(ldap_result_id, 0)
                    #print result_type, ldap.RES_SEARCH_ENTRY, result_data
                    if (result_data == []):
                        break
                    else:
                        if result_type == ldap.RES_SEARCH_ENTRY:
                            # compose response as we like it
                            # Ticket #754
                            userdata["userid"] = \
                                result_data[0][1].get("oakPrimaryPersonID", [None])[0]

                            for ukey, uval in self.userinfo.iteritems():
                                if uval in result_data[0][1]:
                                # An attribute can hold more than 1 value
                                # So we only take the first one at the moment
                                #    result_data[0][1][v][0]
                                # If we want to get all
                                #    result_data[0][1][v] gives us a list
                                    rdata = result_data[0][1][uval][0]
                                    try:
                                        udata = rdata.decode(ENCODING)
                                    except:
                                        udata = rdata
                                    userdata[ukey] = udata

                            resultList.append(userdata)
            except ldap.LDAPError as exce:
                log.error("[getUserList] LDAP error: %r" % exce)
            except Exception as exce:
                log.error("[getUserList] error during LDAP access: %r" % exce)
                log.error("[getUserList] %s" % traceback.format_exc())

            if resultList:
                return resultList

        return ""

        # Code to list all Oak realms just in case we ever need to
        '''        auth = ldap.sasl.gssapi("")
        l_obj = ldap.initialize("ldap://ldap.oak.ox.ac.uk:389", trace_level=0)

        l_obj.network_timeout = self.timeout
        l_obj.start_tls_s()
        l_obj.sasl_interactive_bind_s("",auth)

        resultList = []

        groupinfo = {
            "username": "oakUnitCode",
            "email" : "oakUnitCode",
            "surname" : "oakUnitCode",
            "givenname" : "displayName"
        }

       attrlist = []
        for ukey, uval in groupinfo.iteritems():
            attrlist.append(str(uval))

        searchFilter = "(&(oakUnitCode=*))"

        try:
            ldap_result_id = l_obj.search_ext("ou=units,dc=oak,dc=ox,dc=ac,dc=uk",
                             ldap.SCOPE_SUBTREE,
                             filterstr=searchFilter.encode(ENCODING),
                             sizelimit=1000,
                             attrlist=attrlist)

            while 1:
                userdata = {}
                result_type, result_data = l_obj.result(ldap_result_id, 0)
                #print result_type, ldap.RES_SEARCH_ENTRY, result_data
                if (result_data == []):
                    break
                else:
                    if result_type == ldap.RES_SEARCH_ENTRY:
                        # compose response as we like it
                        # Ticket #754
                        userdata["userid"] = \
                            result_data[0][1].get("oakPrimaryPersonID", [None])[0]

                        for ukey, uval in groupinfo.iteritems():
                            if uval in result_data[0][1]:
                                # An attribute can hold more than 1 value
                                # So we only take the first one at the moment
                                #    result_data[0][1][v][0]
                                # If we want to get all
                                #    result_data[0][1][v] gives us a list
                                    rdata = result_data[0][1][uval][0]
                                    try:
                                        udata = rdata.decode(ENCODING)
                                    except:
                                        udata = rdata
                                    userdata[ukey] = udata

                        resultList.append(userdata)

        except ldap.LDAPError as exce:
            log.error("[getUserList] LDAP error: %r" % exce)
        except Exception as exce:
            log.error("[getUserList] error during LDAP access: %r" % exce)
            log.error("[getUserList] %s" % traceback.format_exc())

        if resultList:
            return resultList'''

###eof#########################################################################
