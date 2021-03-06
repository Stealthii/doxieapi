# -*- coding: utf-8 -*-

"""
Copyright 2014 Dan Krause

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""


import socket
from http.client import HTTPResponse


# pylint: disable=invalid-name,too-few-public-methods

class SSDPResponse:
    """Defines an SSDP Response."""
    def __init__(self, sock):
        resp = HTTPResponse(sock)
        resp.begin()
        self.location = resp.getheader("location")
        self.usn = resp.getheader("usn")
        self.st = resp.getheader("st")
        self.cache = resp.getheader("cache-control").split("=")[1]

    def __repr__(self):
        return "<SSDPResponse({location}, {st}, {usn})>".format(
            **self.__dict__
        )


def discover(service, timeout=2, retries=1, mx=3):
    """
    Discover an SSDP advertisment.

    Example:
    ssdp.discover("roku:ecp")
    """
    group = ("239.255.255.250", 1900)
    message = "\r\n".join([
        'M-SEARCH * HTTP/1.1',
        'HOST: {0}:{1}',
        'MAN: "ssdp:discover"',
        'ST: {st}', 'MX: {mx}', '', ''])
    socket.setdefaulttimeout(max(timeout, mx))
    responses = {}
    for _ in range(retries):
        sock = socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP
        )
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.sendto(message.format(*group, st=service, mx=mx).encode(), group)
        while True:
            try:
                response = SSDPResponse(sock)
                responses[response.location] = response
            except socket.timeout:
                break
    return responses.values()
