import math
import os
from urllib.parse import urljoin

import requests

class UnsupportedRemoteExtraction(Exception):
    pass

class STIXObjectRetriever:
    def __init__(self, host="ctibutler") -> None:
        if host == "ctibutler":
            self.api_root = os.environ["CTIBUTLER_BASE_URL"] + "/"
            self.api_key = os.environ.get("CTIBUTLER_API_KEY")
        elif host == "vulmatch":
            self.api_root = os.environ["VULMATCH_BASE_URL"] + "/"
            self.api_key = os.environ.get("VULMATCH_API_KEY")
        else:
            raise UnsupportedRemoteExtraction("The host `%s` is not supported", host)

        self.session = requests.Session()
        self.session.headers.update(
            {
                "API-KEY": self.api_key,
            }
        )
    
    def retrieve_objects(self, path, key='objects'):
        url = urljoin(self.api_root, path)
        retval = []
        page = 1
        while True:
            resp = self.session.get(url, params=dict(page=page, page_size=50))
            resp.raise_for_status()
            d = resp.json()
            if len(d[key]) == 0:
                break
            retval.extend(d[key])
            page += 1
            if d.get('total_results_count', math.inf) <= len(retval):
                break
        return retval
