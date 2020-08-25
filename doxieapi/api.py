# -*- coding: utf-8 -*-

"""
doxieapi.api
~~~~~~~~~~~~

An API client implementation for the Doxie Scanner API.
"""

import os
import time
import json
from configparser import ConfigParser
from http.cookiejar import http2time
from urllib.parse import urlparse, urlunparse, urljoin

import requests

from . import ssdp

DOXIE_SSDP_SERVICE = "urn:schemas-getdoxie-com:device:Scanner:1"
DOXIE_ATTR_MAP = {
    'mac': 'MAC',
    'firmware_wifi': 'firmwareWiFi',
    'connected_to_external_power': 'connectedToExternalPower',
    'has_password': 'hasPassword',
}

# Scans are downloaded in chunks of this many bytes:
DOWNLOAD_CHUNK_SIZE = 1024*8


class DoxieScanner:
    """A client for the Doxie Scanner."""

    basepath = None

    # These attributes will be populated by 'hello' or 'hello_extra' API calls.
    # By default we will pre-populate those from 'hello'.
    _attributes = {}  # type: dict

    def __init__(self, basepath, password=None, load_attributes=True):
        """Create a client session to the Doxie API.

        Arguments:
            basepath -- the base path to the Doxie API
            password -- (optional) the password to authenticate with
        """

        self.basepath = basepath
        self.session = requests.Session()

        # Authentication for Doxie API
        if password:
            self.session.auth = ('doxie', password)

        if load_attributes:
            self._fetch_attributes()
            if self.has_password and not self.session.auth:
                # Set up authentication if possible
                self.session.auth = self._load_password()

    def __str__(self):
        """
        >>> doxie = DoxieScanner("http://192.168.100.1:8080/",
        ...                      load_attributes=False)
        >>> doxie.name = "Doxie_00AAFF"
        >>> doxie.model = "DX250"
        >>> str(doxie)
        'Doxie model DX250 (Doxie_00AAFF) at http://192.168.100.1:8080/'
        """
        return "Doxie model {} ({}) at {}".format(
            self.model, self.name, self.basepath)

    def __repr__(self):
        """
        >>> doxie = DoxieScanner("http://192.168.100.1:8080/",
        ...                      load_attributes=False)
        >>> doxie.name = "Doxie_00AAFF"
        >>> doxie.model = "DX250"
        >>> str(doxie)
        '<DoxieScanner: Doxie model DX250 (Doxie_00AAFF) at
        http://192.168.100.1:8080/>'
        """
        return "<DoxieScanner: {}>".format(str(self))

    def __getattr__(self, name):
        """Attempts to retrieve an attribute of the Doxie model.
        Raises an AttributeError if it fails.

        """
        # map snake_case naming to Doxie camelCasing if applicable
        attr = DOXIE_ATTR_MAP.get(name) or name

        # Returns cached attribute if exists
        if attr in self._attributes:
            return self._attributes[attr]

        # Retrieves from API if possible
        try:
            return self._fetch_attributes(attr)
        except KeyError as err:
            raise AttributeError(
                "'{}' object has no attribute '{}'".format(
                    type(self).__name__, name)
            ) from err

    @classmethod
    def discover(cls):
        """
        Return a list of DoxieScanner instances, one per device found via
        SSDP.
        """
        doxies = []
        for response in ssdp.discover(DOXIE_SSDP_SERVICE, mx=1, retries=3):
            if DOXIE_SSDP_SERVICE not in response.usn:
                continue  # skip over non-Doxie responses
            scheme, netloc, _, _, _, _ = urlparse(response.location)
            basepath = urlunparse((scheme, netloc, '/', '', '', ''))
            doxies.append(DoxieScanner(basepath))
        return doxies

    def _api_url(self, path):
        """
        >>> doxie._api_url("/scans.json")
        'http://192.168.100.1:8080/scans.json'
        >>> doxie._api_url("/networks/available.json")
        'http://192.168.100.1:8080/networks/available.json'
        """
        return urljoin(self.basepath, path)

    def _api_call(self, path, return_json=True):
        """
        Makes a request to the Doxie scanner on the given path,
        authenticating if necessary.
        Assumes the result is JSON, and returns the result of parsing it.
        Call with return_json=False to skip the JSON parsing step.
        """
        url = self._api_url(path)
        response = self._get_url(url)
        return response.json() if return_json else None

    def _get_url(self, url, stream=False):
        """
        Performs a GET to a URL, including authentication
        if required.
        Checks that the response status code is 200 before
        returning the response.
        """
        response = self.session.get(url, stream=stream)
        if response.status_code != requests.codes.ok:
            response.raise_for_status()
        return response

    def _fetch_attributes(self, attribute=None):
        """
        Retrieves attributes from the 'hello' or 'hello_extra' API calls.
        If 'attribute' provided, we will attempt to load it, and raise an error
        if not found.
        """
        self._attributes.update(self._api_call("/hello.json"))
        if attribute and attribute not in self._attributes:
            # Additional call for more information
            self._attributes.update(self._api_call("/hello_extra.json"))

        if attribute:
            # Raises KeyError if doesn't exist
            return self._attributes[attribute]

        return True

    def _load_password(self):
        """
        Load the password for this Doxie's MAC address from ~/.doxieapi.ini,
        or another path specified by the DOXIEAPI_CONFIG_PATH env variable
        """
        config_path = os.path.expanduser(
            os.environ.get("DOXIEAPI_CONFIG_PATH", "~/.doxieapi.ini")
        )
        config = ConfigParser()
        config.read(config_path)
        try:
            return ('doxie', config[self.mac]['password'])
        except KeyError as err:
            raise Exception(
                "Couldn't find password for Doxie {} in {}".format(
                    self.mac, config_path)
            ) from err

    @property
    def scans(self):
        """
        Returns a list of scans available on the Doxie
        """
        return self._api_call("/scans.json")

    @property
    def recent(self):
        """
        Returns the path of the most recent scan available on the Doxie.
        This seems to be cached on the Doxie and may refer to a scan
        which has subsequently been deleted.
        """
        return self._api_call("/scans/recent.json")['path']

    def restart_wifi(self):
        """
        Restarts the wifi on the Doxie
        """
        self._api_call("/restart.json", return_json=False)

    def download_scan(self, path, output_dir):
        """
        Downloads a scan at the given path to the given local dir,
        preserving the filename.
        Will raise an exception if the target file already exists.
        Returns the path of the downloaded file.
        """
        if not path.startswith("/scans"):
            path = "/scans{}".format(path)
        url = self._api_url(path)
        response = self._get_url(url, stream=True)
        output_path = os.path.join(output_dir, os.path.basename(path))
        if os.path.isfile(output_path):
            raise FileExistsError(output_path)
        with open(output_path, 'wb') as output:
            for chunk in response.iter_content(chunk_size=DOWNLOAD_CHUNK_SIZE):
                output.write(chunk)
        # Set file timestamp to that of the file we downloaded
        timestamp = http2time(response.headers.get('Last-Modified'))
        os.utime(output_path, (timestamp,)*2)

        return output_path

    def download_scans(self, output_dir):
        """
        Downloads all available scans from this Doxie to the specified dir,
        preserving the filenames from the scanner.
        Returns a list of the downloaded files.
        """
        output_files = []
        for scan in self.scans:
            output_files.append(self.download_scan(scan['name'], output_dir))
        return output_files

    def delete_scan(self, path, retries=3, timeout=5):
        """
        Deletes a scan from the Doxie.
        This method may be slow; from the API docs:
           Deleting takes several seconds because a lock on the internal
           storage must be obtained and released. Deleting may fail if the lock
           cannot be obtained (e.g., the scanner is busy), so consider retrying
           on failure conditions.
        This method will attempt the deletion multiple times with a timeout
        between attempts - controlled by the retries and timeout (seconds)
        params.
        Returns a boolean indicating whether the deletion was successful.
        """
        if not path.startswith("/scans"):
            path = "/scans{}".format(path)
        url = self._api_url(path)
        for attempt in range(retries):
            response = self.session.delete(url)
            if response.status_code == requests.codes.no_content:
                return True
            if attempt < retries-1:
                time.sleep(timeout)
        return False

    def delete_scans(self, paths, retries=3, timeout=5):
        """
        Deletes multiple scans from the Doxie.
        This method may be slow; from the API docs:
           Deleting takes several seconds because a lock on the internal
           storage must be obtained and released. Deleting may fail if the lock
           cannot be obtained (e.g., the scanner is busy), so consider retrying
           on failure conditions.
        This method will attempt the deletion multiple times with a timeout
        between attempts - controlled by the retries and timeout (seconds)
        params.
        Returns a boolean indicating whether the deletion was successful.
        The deletion is considered successful by the Doxie if at least one scan
        was deleted, it seems.
        """
        url = self._api_url("/scans/delete.json")
        for attempt in range(retries):
            response = self.session.post(url, data=json.dumps(paths))
            if response.status_code == requests.codes.no_content:
                return True
            if attempt < retries-1:
                time.sleep(timeout)
        return False
