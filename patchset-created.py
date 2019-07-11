#!/usr/bin/env python
#
# Copyright (c) 2019, Eric Wollesen <ericw@xmtp.net>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

"""
    Gerrit Webhook
"""

__author__ = "Eric Wollesen"
__author_email__ = "ericw@xmtp.net"

import base64
import json
import json
import os
import re
import string
import sys
import urllib
import urllib2
import urlparse

from optparse import OptionParser

GERRIT_URL = os.environ.get("GERRIT_URL", "https://gerrit.example.com")
GERRIT_USERNAME = os.environ.get("GERRIT_USERNAME", "")
GERRIT_PASSWORD = os.environ.get("GERRIT_PASSWORD", "")
GERRIT_REALM = os.environ.get("GERRIT_REALM", "")
SRHT_BUILDS_URL = os.environ.get("SRHT_BUILDS_URL", "https://builds.sr.ht/api/jobs")
SRHT_OAUTH_TOKEN = os.environ.get("SRHT_OAUTH_TOKEN", "deadbeef")

# ['/var/gerrit/hooks/patchset-created',
# '--change', 'testing~master~Ic3b2b1a6bd84e2f28e00960ff0b850806a619cd4',
# '--kind', 'REWORK',
# '--change-url', 'https://gerrit.tribalmetrics.com/c/testing/+/2',
# '--change-owner', '"Name of user not set (1000000)"',
# '--change-owner-username', 'eric',
# '--project', 'testing',
# '--branch', 'master',
# '--topic', '',
# '--uploader', '"Name of user not set (1000000)"',
# '--uploader-username', 'eric',
# '--commit', 'ca40760e71f0bcef1e6e5393baef014f0f414852',
# '--patchset', '9']

def installGerritAuth():
    if GERRIT_REALM != "":
        auth_handler = urllib2.HTTPBasicAuthHandler()
        auth_handler.add_password(realm=GERRIT_REALM,
                                  uri=GERRIT_URL,
                                  user=GERRIT_USERNAME,
                                  passwd=GERRIT_PASSWORD)
        opener = urllib2.build_opener(auth_handler)
        urllib2.install_opener(opener)


def webhook(options):
    url = dotBuildsURL(options.change, options.project, options.patchset)
    try:
        f = urllib2.urlopen(url)
    except urllib2.HTTPError, e:
        print e.code, e.reason
        raise e
    except urllib2.URLError, e:
        print e.reason
        raise e

    for line in string.split(base64.b64decode(f.read()), "\n"):
        if line == "":
            continue
        # The last column of the response contains the files' names.
        path = string.split(line)[-1]
        submitBuild(options.change, options.commit, path, options.branch,
                    options.change_owner_username, options.project)


def dotBuildsURL(change, project, patchset):
    changeset = int(string.split(change, "/")[-1])
    changesetLast2 = changeset % 100
    t = "%s/plugins/gitiles/%s/+/refs/changes/%02d/%d/%d/.builds?format=TEXT"
    return t % (GERRIT_URL, project, changesetLast2, changeset, int(patchset))


def escapeTags(tags=[]):
    """Each string must use only lowercase alphanumeric characters, or any of "-_."
    """

    regexp = re.compile(r"[^a-z0-9\-_.]+")
    escaped = []

    for tag in tags:
        noSlash, _ = re.subn("/+", ".", tag, 0)
        r, _ = regexp.subn("", noSlash, 0)

        escaped.append(r)

    return escaped


def getSubject(change):
    try:
        url = "%s/changes/%s" % (GERRIT_URL, change,)
        print("getSubject url %s" % (url,))
        rawJSON = urllib2.urlopen(url).read()
        # Delete up to the first '{' I'm not sure why, but there's garbage in
        # front of it.
        trimmed = rawJSON[string.index(rawJSON, "{"):]
        response = json.loads(trimmed)
        return response["subject"]
    except urllib2.HTTPError, e:
        print e.code, e.reason
        return ""
    except Exception, e:
        print e
        return ""

def submitBuild(change, commit, path, branch, username, project):
    path = urllib.quote(".builds/" + path)
    t = "%s/changes/%s/revisions/%s/files/%s/content"
    url = t % (GERRIT_URL, change, commit, urllib.quote(path, ""),)
    try:
        f = urllib2.urlopen(url)
    except urllib2.HTTPError, e:
        print e.code, e.reason
        raise e
    manifest = base64.b64decode(f.read())

    note = "Build triggered by gerrit patchset creation."
    subject = getSubject(change)
    if subject != "":
        note = subject

    print("note: %s" % (note,))

    postData = {
        "manifest": manifest,
        # TODO: Use first line of the commit's message as the note?
        "note": note,
        "tags": escapeTags([gerritHost(GERRIT_URL), project, branch, username,]),
        "execute": True,
        "secrets": True,
    }
    try:
        req = urllib2.Request(SRHT_BUILDS_URL)
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", "token %s" % (SRHT_OAUTH_TOKEN,))
        f2 = urllib2.urlopen(req, json.dumps(postData))
    except urllib2.HTTPError, e:
        print e.code, e.reason
        raise e

    print f2.read()


def gerritHost(url):
    url = urlparse.urlparse(url)
    if url.netloc != "":
        return url.netloc
    return url


def main():
    parser = OptionParser(usage="usage: %prog <required options>")
    parser.add_option("--change", help="Change identifier")
    parser.add_option("--kind", help="Change kind")
    parser.add_option("--change-url", help="Change url")
    parser.add_option("--change-owner", help="Change owner")
    parser.add_option("--change-owner-username", help="Change owner username")
    parser.add_option("--project", help="Project path in Gerrit")
    parser.add_option("--branch", help="Branch name")
    parser.add_option("--topic", help="Topic name")
    parser.add_option("--uploader", help="Uploader")
    parser.add_option("--uploader-username", help="Uploader username")
    parser.add_option("--commit", help="Git commit hash")
    parser.add_option("--patchset", help="Patchset")
    options, args = parser.parse_args()
    installGerritAuth()
    webhook(options)

if __name__ == "__main__":
    try:
        main()
    except Exception, e:
        sys.stderr.write("error %r\n" % e)
        sys.exit(1)
