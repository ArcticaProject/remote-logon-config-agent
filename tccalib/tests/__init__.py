# Copyright 2012 Canonical Ltd.  This software is licensed under the GNU
# General Public License version 3 (see the file LICENSE).


__metaclass__ = type


import urllib.request, urllib.error, urllib.parse
from unittest import TestCase
import base64

import pycurl
from io import BytesIO

from tccalib import (
    CertificateVerificationFailed,
    CouldNotConnect,
    GetMazaData,
    GetMazaDataAPI1,
    GetMazaDataAPI2,
    GetMazaDataAPI3,
    GetMazaDataAPI4,
    PycURLGetter,
    Unauthorized,
    )


class FakeGetResponseBody:
    """Fake to raise a 401 when get_response_body is called."""

    def get_response_body(self, request, verify_ssl):
        raise urllib.error.HTTPError(None, 401, None, None, None)


class GetMazaDataFaked(GetMazaData):
    """Subclass of GetMazaData for testing."""

    api_version = 34

    def __init__(self, username=None, server_root=None):
        super(GetMazaDataFaked, self).__init__(username, username, server_root)

    def make_request(self):
        pass


class TestGetMazaData(TestCase):

    def test_get_data_unauthorized(self):
        """If a 401 is encountered, Unauthorized is raised."""
        api_client = GetMazaDataFaked()
        api_client.getter = FakeGetResponseBody()
        with self.assertRaises(Unauthorized):
            api_client.get_data()

    def test_get_api_url_default(self):
        """Default URL is as expected."""
        url = GetMazaDataFaked().get_api_url()
        self.assertEqual('https://uccs.landscape.canonical.com/api/34/',
                         url)

    def test_get_api_url_explicit(self):
        """URL is as expected with specified server_root."""
        url = GetMazaDataFaked(server_root='http://foo').get_api_url()
        self.assertEqual('http://foo/api/34/', url)


class TestGetMazaDataAPI1(TestCase):

    def test_make_request(self):
        """v1 requests have correct URL and no Auth header."""
        getter = GetMazaDataAPI1('foo', 'bar')
        request = getter.make_request()
        self.assertEqual('https://uccs.landscape.canonical.com/api/1/foo/bar',
                         request.get_full_url())
        self.assertIs(None, request.headers.get('Authorization'))


class TestGetMazaDataAPI2(TestCase):

    def test_make_request(self):
        """v2 requests have correct URL and Auth header."""
        getter = GetMazaDataAPI2('foo', 'bar')
        request =  getter.make_request()
        credentials = base64.encodebytes(b'foo:bar').decode('ascii')
        expected = 'Basic %s' % credentials
        self.assertEqual('GET', request.get_method())
        self.assertEqual('https://uccs.landscape.canonical.com/api/2/foo',
                         request.get_full_url())
        self.assertEqual(expected, request.headers['Authorization'])


class TestGetMazaDataAPI3(TestCase):

    def test_make_request(self):
        """v3 requests have correct URL and Auth header."""
        getter = GetMazaDataAPI3('foo', 'bar')
        request =  getter.make_request()
        credentials = base64.encodebytes(b'foo:bar').decode('ascii')
        expected = 'Basic %s' % credentials
        self.assertEqual('GET', request.get_method())
        self.assertEqual('https://uccs.landscape.canonical.com/api/3/foo',
                         request.get_full_url())
        self.assertEqual(expected, request.headers['Authorization'])


class TestGetMazaDataAPI4(TestCase):

    def test_make_request(self):
        """v4 requests have correct URL and Auth header."""
        getter = GetMazaDataAPI4('foo', 'bar')
        request =  getter.make_request()
        credentials = base64.encodebytes(b'foo:bar').decode('ascii')
        expected = 'Basic %s' % credentials
        self.assertEqual('GET', request.get_method())
        self.assertEqual('https://uccs.landscape.canonical.com/api/4/',
                         request.get_full_url())
        self.assertEqual(expected, request.headers['Authorization'])


class FakeCurl:
    """Fake pycurl.Curl for testing PycURLGetter."""

    def __init__(self, response_status=200, body='', header='',
                 effective_url='http://example.org/', perform_error=None):
        self.options = {}
        self.info = {}
        self.response_status = response_status
        self.response_header = bytes(header, 'UTF-8')
        self.response_body = bytes(body, 'UTF-8')
        self.effective_url=effective_url
        self.perform_error = perform_error

    def setopt(self, key, value):
        self.options[key] = value

    def perform(self):
        if self.perform_error is not None:
            raise self.perform_error
        self.info[pycurl.EFFECTIVE_URL] = self.effective_url
        self.info[pycurl.HTTP_CODE] = self.response_status
        self.options[pycurl.HEADERFUNCTION](self.response_header)
        self.options[pycurl.WRITEFUNCTION](self.response_body)

    def getinfo(self, key):
        return self.info[key]


class TestPycURLGetter(TestCase):

    def test_init(self):
        """Init should set the WRITEFUNCTION and HEADERFUNCTION."""
        getter = PycURLGetter(FakeCurl())
        options = getter.curl.options
        self.assertIsNot(None, options[pycurl.WRITEFUNCTION])
        self.assertIsNot(None, options[pycurl.HEADERFUNCTION])

    @staticmethod
    def make_request():
        return GetMazaDataAPI3('pete', 'pass').make_request()

    def test_prepare_curl(self):
        """prepare_curl sets URL and auth header."""
        curl = FakeCurl()
        getter = PycURLGetter(curl)
        request = self.make_request()
        getter.prepare_curl(request)
        self.assertEqual(request.get_full_url(), curl.options[pycurl.URL])
        self.assertEqual(['Authorization: Basic cGV0ZTpwYXNz\n'],
                         curl.options[pycurl.HTTPHEADER])

    def test_prepare_curl_ssl_verify(self):
        """SSL cert verification can be disabled for testing purposes."""
        curl = FakeCurl()
        getter = PycURLGetter(curl)
        getter.prepare_curl(self.make_request())
        self.assertTrue(curl.options[pycurl.SSL_VERIFYPEER])
        getter.verify_ssl = False
        getter.prepare_curl(self.make_request())
        self.assertFalse(curl.options[pycurl.SSL_VERIFYPEER])

    def test_handle_reponse(self):
        """On success, handle_response returns response body."""
        curl = FakeCurl(body='My body!', header='My header!',
                        effective_url='http://example.com/')
        getter = PycURLGetter(curl)
        output = getter.handle_response()
        self.assertEqual('My body!', output)
        self.assertEqual('My header!', getter.response_header.getvalue().decode('UTF-8'))
        self.assertEqual('http://example.com/',
                         getter.curl.getinfo(pycurl.EFFECTIVE_URL))

    def test_handle_response_http_error(self):
        """On http error, handle_response raises urllib.error.HTTPError."""
        curl = FakeCurl(500, 'My body!', '\nContent-type: fake\n\n')
        getter = PycURLGetter(curl)
        try:
            getter.handle_response()
        except urllib.error.HTTPError as e:
            httpe = e
        else:
            self.fail('No error was raised.')
        try:
            httpe.geturl()
        except AttributeError as attre:
            self.assertEqual("'HTTPError' object has no attribute 'url'",
                             str(attre))
        self.assertEqual(500, httpe.getcode())
        self.assertEqual('My body!', httpe.msg.decode('UTF-8'))
        self.assertEqual([('Content-type', 'fake')], httpe.hdrs.items())

    def test_handle_response_connection_error(self):
        """On connection error, handle_response raises CouldNotConnect."""
        error = pycurl.error(pycurl.E_COULDNT_CONNECT)
        getter = PycURLGetter(FakeCurl(perform_error=error))
        with self.assertRaises(CouldNotConnect):
            getter.handle_response()

    def test_cert_verification_failed(self):
        """Cert verification error raises CertificateVerificationFailed."""
        error = pycurl.error(pycurl.E_SSL_CACERT)
        getter = PycURLGetter(FakeCurl(perform_error=error))
        with self.assertRaises(CertificateVerificationFailed):
            getter.handle_response()

    def test_handle_response_pycurl_error(self):
        """PycURLGetter allows other errors to propagate."""
        error = pycurl.error(pycurl.E_MULTI_OUT_OF_MEMORY)
        getter = PycURLGetter(FakeCurl(perform_error=error))
        with self.assertRaises(pycurl.error):
            getter.handle_response()

    def test_get_response_body(self):
        """On success, get_response_body returns response body."""
        curl = FakeCurl(body='My body!', header='My header!',
                        effective_url='http://example.com/')
        request = GetMazaDataAPI3('pete', 'pass').make_request()
        output = PycURLGetter.get_response_body(request, _curl=curl)
        self.assertEqual('My body!', output)
