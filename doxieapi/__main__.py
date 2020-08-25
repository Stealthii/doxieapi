# -*- coding: utf-8 -*-

"""
doxieapi.__main__
~~~~~~~~~~~~~~~~~

Application that runs when executing the module with -m.
"""

import argparse
import os
import sys

from .api import DoxieScanner


def main(servers=None, delete=False, output_dir=None):
    """
    Grab all available scan images and save them to the current working
    directory.
    """

    if servers:
        print("{} scanners defined, connecting...".format(len(servers)))
        doxies = [DoxieScanner(server) for server in servers]
    else:
        print("No scanners defined, trying auto-discover...")
        doxies = DoxieScanner.discover()
    if not doxies:
        print("No scanners discovered, exiting")
        sys.exit(1)
    for doxie in doxies:
        print("Connecting to {}.".format(doxie))
        names = [scan['name'] for scan in doxie.scans]
        if not names:
            print("No scans found, skipping...")
            continue
        print("Downloading {} scans...".format(len(names)))
        saves = [
            os.path.basename(name)
            for name in doxie.download_scans(names, output_dir)
        ]
        for scan in saves:
            print("Saved {}".format(scan))
        print("Successfully downloaded {} of {} scans".format(len(saves),
                                                              len(names)))
        if delete:
            # Only delete files we have successfully downloaded
            names_to_delete = [
                name for name in names
                if name.endswith(tuple(saves))
            ]
            print("Deleting {} successfully downloaded scans...".format(
                len(names_to_delete)))
            if doxie.delete_scans(names_to_delete):
                print("Successfully deleted scans!")
            else:
                print("Failed to delete scans.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Doxie scanner auto-download tool")
    parser.add_argument(
        '--server', dest='servers', action='append',
        help="Doxie server to connect to. Multiple possible.")
    parser.add_argument(
        '--delete', action='store_true',
        help="Automatically remove scans after successful download")
    parser.add_argument(
        '--output-dir', default=os.getcwd(),
        help="Output directory for the scans")
    args = parser.parse_args()
    main(**vars(args))
