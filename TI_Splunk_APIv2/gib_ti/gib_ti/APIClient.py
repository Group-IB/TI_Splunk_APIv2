import urllib3
import requests

from urllib.parse import urljoin
from requests.auth import HTTPBasicAuth
from gib_ti.gib_ti.IntegrationException import IntegrationException
from gib_ti.gib_ti.Saver import Saver


class APIClient(object):
    """Main client class.
    Attributes:
        username (str): Group IB Login.
        api_key (str): Generated API_KEY.
        api_url (str): API URL
        proxies (dict): Python requests Proxies
	last_seq_update (int): seqUpdate of last gotten feeds portion

    """
    def __init__(self, username, api_key, api_url):
        self.username = username
        self.api_key = api_key
        self.api_url = api_url
        self.headers = {
            "Accept": "*/*"
        }
        self.proxies = {}

        self.last_seq_update = None

    def _send_request(self, url, params):
        """
        Send Request and get json object back.
        Args:
            url: url
            params: dict with params for hTTP GET request

        Returns:
            valid json data.
        """
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        params = {k: v for k, v in params.items() if v is not None}
        try:
            response = requests.get(url,
                                    auth=HTTPBasicAuth(self.username, self.api_key),
                                    params=params,
                                    headers=self.headers,
                                    proxies=self.proxies,
                                    verify=False)
        except ValueError as e:
            raise IntegrationException("There are some connection troubles: {}".format(e))

        status_code = response.status_code
        status_codes_msgs = {
            401: "Bad Credentials.",
            403: "Something is wrong with your account, please, contact GIB.",
            404: "Not found. There is no such data on server.",
            500: "There are some troubles on server with your request.",
            301: "Verify that your IP is whitelisted by Group IB."
        }

        if status_code in status_codes_msgs:
            raise IntegrationException(status_codes_msgs[status_code])
        else:
            try:
                if status_code == 200: 
                    return response.json()
                else:
                    raise IntegrationException("OOPS, something wrong!")
            except Exception as e:
                raise IntegrationException("Something wrong: {}".format(e))

    def _verify_limit(self, collection, limit):
        """Check if limit is valid.
        Args:
            collection: GIB collection name
            limit: limit
        """
        
        big_data_collections = ["apt/threat", "hi/threat"]
        if collection in big_data_collections and limit > 20:
            raise IntegrationException("Max limit for {} collections is 20".format(", ".join(big_data_collections)))
        elif limit > 100:
            raise IntegrationException("Max limit is 100 items")

    def set_proxy(self, protocol, address, port):
        """
        Set proxy server for API Client requests.
        Args:
            protocol: http/https
            address: valid IP address
            port: port
        """
        self.proxies = {
            protocol: ":".join([address, str(port)])
        }

    def get_item_by_id(self, collection, item_id):
        """ Get collection item with current ID.
        Args:
            collection: Valid GIB collection Name.
            item_id: Group Ib TI item ID.
        Returns:
            Valid dict generated from json item.
        """
        req_url = urljoin(self.api_url, collection + "/" + item_id)
        resp = self._send_request(req_url, {})
        return resp

    def get_next_portion_by_seq_update(self, collection, seq_update, limit=100):
        """Get next feeds portion starting from next feed sequenceId for current collection.
        Args:
            collection: Collection name
            seq_update: seqUpdate to get portion with
            limit: limit
        Returns:
            items list
        """
        self._verify_limit(collection, limit)
        req_url = urljoin(self.api_url, collection + "/" + "updated")
        params = {
            "seqUpdate": str(seq_update),
            "limit": limit
        }
        next_portion = self._send_request(req_url, params)
        return next_portion.get('items')

    def get_seq_update_by_date(self, collection, date):
        """Get seqUpdate from server for provided date.
        Args:
            collection: Collection name
            date: format = YYYY-MM-DD
        Returns:
            seqUpdate
        """
        req_url = urljoin(self.api_url, "sequence_list")
        params = {
            "date": date,
            "collection": collection
        }
        seq_update = self._send_request(req_url, params).get("list").get(collection)
        return seq_update

    def get_items_count_by_seq_update(self, collection, seq_update):
        """ Get count of feeds on server for current collection.
        Args:
            collection: GIB collection name
            seq_update: seqUpdate value
        Returns:
            count
        """
        req_url = urljoin(self.api_url, collection + "/" + "/updated")
        params = {
            "seqUpdate": seq_update
        }
        count = self._send_request(req_url, params).get('count')
        return count

    def get_collections_list(self):
        """Get list of all available collections.
        Returns:
            list with all available collections.
        """
        req_url = urljoin(self.api_url, "sequence_list")
        response = self._send_request(req_url, {})
        return list(response.get("list").keys())

    def init_update_session(self, collection, seq_update, limit=100, processor=None,
                            save_as_json=False, data_dir="data/"):
        """Get new feeds from server starting with next feed after provided seqUpdate.
        Args:
            collection: GIB Collection name
            seq_update: seqUpdate to start upload with
            limit: portion max size
            processor: function to process feed portion
            save_as_json: this option will save feeds in json in data_dir
            data_dir: directory to store data in
        """
        self._verify_limit(collection, limit)
        while True:
            portion = self.get_next_portion_by_seq_update(collection, seq_update, limit)
            if len(portion) == 0:
                break
            else:
                if processor:
                    processor(portion, collection)
                if save_as_json:
                    s = Saver(collection, "json", data_dir)
                    s.save(portion)
                seq_update = portion[-1].get("seqUpdate")
                self.last_seq_update = seq_update

    def get_items_count_in_query(self, collection, df=None, dt=None, q=None, limit=1):
        """Get count of items found on server with provided search params
        Args:
            collection: GIB collection name
            df: search start date(format: YYYY-MM-DD)
            dt: search end date(format: YYYY-MM-DD)
            q: search query
            limit: portion max size
        Returns:
            feeds count
        """
        params = {
            "df": df,
            "dt": dt,
            "q": q,
            "limit": limit
        }
        req_url = urljoin(self.api_url, collection)
        response =  self._send_request(req_url, params)
        return response.get('count')
        

    def init_searching_session(self, collection, df=None, dt=None, q=None, limit=100, processor=None,
                               save_as_json=False, data_dir="data/"):
        """ Start searching session in collection with provided params.
        Args:
            collection: GIB Collection name
            df: search start date(format: YYYY-MM-DD)
            dt: search end date(format: YYYY-MM-DD)
            q: search Query
            limit: portion max size
            processor: function to process feeds portion
            save_as_json: this option will save feeds in json in data_dir
            data_dir: directory to store data in
        """
        self._verify_limit(collection, limit)

        params = {
            "df": df,
            "dt": dt,
            "q": q,
            "limit": limit
        }
        req_url = urljoin(self.api_url, collection)

        response = self._send_request(req_url, params)
        result_id = response.get("resultId")
        portion = response.get("items")

        params = {
            "resultId": result_id
        }

        while True:
            if len(portion) == 0:
                break

            if processor:
                processor(portion)
            if save_as_json:
                s = Saver(collection,"json", data_dir)
                s.save(portion)

            portion = self._send_request(req_url, params).get("items")
