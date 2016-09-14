# Copyright 2012 Canonical Ltd.  This software is licensed under the GNU
# General Public License version 3 (see the file LICENSE).

__metaclass__ = type


import errno
from http.client import parse_headers
import socket
from io import BytesIO, StringIO
from urllib.parse import quote
import urllib.request, urllib.error
import base64

import pycurl


class UserError(Exception):
    """An error message that should be presented to the user."""

    def __init__(self, msg=None):
        if msg is None:
            msg = self.__doc__
        super(UserError, self).__init__(msg)


class Unauthorized(UserError):
    """Invalid username or password"""

    status = 2


class CouldNotConnect(UserError):
    """Could not connect"""

    status = 3


class CertificateVerificationFailed(UserError):
    """Certificate verification failed"""

    status = 4


class URLLibGetter:
    """Get data from URLs using URLib."""

    @staticmethod
    def get_response_body(request, verify_ssl):
        """Return the body of the response to the supplied request.

        :param request: A urllib2.Request
        :param verify_ssl: Unused
        :raises CouldNotConnect: if there is a connection error.
        """
        try:
            return urllib.request.urlopen(request).read()
        except urllib.error.URLError as e:
            if not isinstance(e.args[0], socket.error):
                raise
            if e.args[0].errno == errno.ECONNREFUSED:
                raise CouldNotConnect
            raise


class PycURLGetter:
    """Get data from URLs using PycURL."""

    def __init__(self, _curl=None):
        if _curl is None:
            _curl = pycurl.Curl()
        self.curl = _curl
        self.result = BytesIO()
        self.response_header = BytesIO()
        self.curl.setopt(pycurl.HEADERFUNCTION, self.response_header.write)
        self.curl.setopt(pycurl.WRITEFUNCTION, self.result.write)
        self.verify_ssl = True

    def prepare_curl(self, request):
        """Prepare the curl object for the supplied request.

        :param request: a urllib2.Request instance.
        """
        self.curl.setopt(pycurl.URL, request.get_full_url())
        request_headers = ['%s: %s' % item for
                           item in list(request.headers.items())]
        self.curl.setopt(pycurl.HTTPHEADER, request_headers)
        self.curl.setopt(pycurl.SSL_VERIFYPEER, self.verify_ssl)

    @classmethod
    def get_response_body(cls, request, verify_ssl=True, _curl=None):
        """Return the body of the response to the supplied request.

        :param request: A urllib2.Request instance.
        :param verify_ssl: If true, verify SSL certificates.
        :param _curl: The pycurl.Curl object to use (for testing).
        :raises CouldNotConnect: if there is a connection error.
        :raises CertificateVerificationFailed: if the SSL certificate could
            not be verified.
        :raises HTTPError: if the response status is not 200.
        """
        instance = cls(_curl)
        instance.verify_ssl = verify_ssl
        instance.prepare_curl(request)
        return instance.handle_response()

    def handle_response(self):
        """Perform the curl operation and handle the response.

        :return: The body of the response on success.
        :raises CouldNotConnect: if there is a connection error.
        :raises CertificateVerificationFailed: if the SSL certificate could
            not be verified.
        :raises HTTPError: if the response status is not 200.
        """
        try:
            self.curl.perform()
        except pycurl.error as e:
            if e.args[0] in (pycurl.E_COULDNT_CONNECT,
                pycurl.E_COULDNT_RESOLVE_HOST):
                    raise CouldNotConnect
            elif e.args[0] == pycurl.E_SSL_CACERT:
                raise CertificateVerificationFailed
            else:
                raise
        status = self.curl.getinfo(pycurl.HTTP_CODE)
        if status == 200:
            return self.result.getvalue().decode('utf-8')
        else:
            lines = self.response_header.getvalue().decode('utf-8').splitlines(True)
            header_ = ''.join(lines[1:])
            headers = parse_headers(BytesIO(header_.encode('ascii')))
            raise urllib.error.HTTPError(
                self.curl.getinfo(pycurl.EFFECTIVE_URL), status,
                self.result.getvalue(), headers, None)


class GetMazaData:
    """Base class for retrieving data from MAZA server."""

    @classmethod
    def run(cls, username, password, server_root=None, verify_ssl=True):
        """Return the requested data.

        :param username: The username of the user.
        :param password: The user's password.
        :param server_root: The root URL to make queries to.
        :param verify_ssl: If true, verify SSL certificates.
        """
        return cls(username, password, server_root).get_data(verify_ssl)

    def __init__(self, username, password, server_root=None):
        self.username = username
        self.password = password
        if server_root is not None:
            self.server_root = server_root
        else:
            self.server_root = 'https://uccs.landscape.canonical.com'
        self.getter = PycURLGetter

    def get_api_url(self):
        """Return the URL for an API version."""
        return '%s/api/%s/' % (self.server_root, self.api_version)

    def get_data(self, verify_ssl=True):
        """Return the data for this version of the API."""
        try:
            return self.getter.get_response_body(self.make_request(),
                                                 verify_ssl)
        except urllib.error.HTTPError as e:
            if e.getcode() == 401:
                raise Unauthorized
            else:
                raise


class GetMazaDataAPI1(GetMazaData):
    """Get the maza data for a given email and password via API v1."""

    api_version = 1

    def make_request(self):
        path = '%s/%s' % (quote(self.username), quote(self.password))
        return urllib.request.Request(self.get_api_url() + path)


class GetMazaDataAPI4(GetMazaData):
    """Get the maza data for a given email and password via API v4."""
    api_version = 4

    def get_url(self):
        return self.get_api_url()

    def make_request(self):
        request = urllib.request.Request(self.get_url())
        credentials = '%s:%s' % (self.username, self.password)
        credentials64 = base64.encodebytes(credentials.encode('ascii'))
        authorization = 'Basic %s' % credentials64.decode('ascii')
        request.add_header('Authorization', authorization)
        return request


class GetMazaDataAPI3(GetMazaDataAPI4):
    """Get the maza data for a given email and password via API v3."""

    api_version = 3

    def get_url(self):
        return self.get_api_url() + quote(self.username)


class GetMazaDataAPI2(GetMazaDataAPI3):
    """Get the maza data for a given email and password via API v2."""

    api_version = 2


api_versions = {
    '1': GetMazaDataAPI1,
    '2': GetMazaDataAPI2,
    '3': GetMazaDataAPI3,
    '4': GetMazaDataAPI4,
    'default': GetMazaDataAPI4,
}
