#!/usr/bin/env python

__author__ = "Anand Tiwari (http://twitter.com/anandtiwarics)"
__contributors__ = ["Anand Tiwari"]
__status__ = "Production"
__license__ = "MIT"

import json

import requests


class arachniAPI(object):
    def __init__(self, host, port, username_api, password_api):

        self.host = host
        self.port = port
        self.username_api = username_api
        self.password_api = password_api

    def scan(self):
        """
        :return: Information about all active scans, grouped by their id.
        """
        return self._request("GET", "/scans")

    def scan_launch(self, data):
        """
        :param data: Ex. {"url": "http://example.com"}
        Default options are:
            {
              "url" : null,
              "http" : {
                "user_agent" : "Arachni/v2.0dev",
                "request_timeout" : 10000,
                "request_redirect_limit" : 5,
                "request_concurrency" : 20,
                "request_queue_size" : 100,
                "request_headers" : {},
                "response_max_size" : 500000,
                "cookies" : {}
              },
              "audit" : {
                "parameter_values" : true,
                "exclude_vector_patterns" : [],
                "include_vector_patterns" : [],
                "link_templates" : []
              },
              "input" : {
                "values" : {},
                "default_values" : {
                  "(?i-mx:name)" : "arachni_name",
                  "(?i-mx:user)" : "arachni_user",
                  "(?i-mx:usr)" : "arachni_user",
                  "(?i-mx:pass)" : "5543!%arachni_secret",
                  "(?i-mx:txt)" : "arachni_text",
                  "(?i-mx:num)" : "132",
                  "(?i-mx:amount)" : "100",
                  "(?i-mx:mail)" : "arachni@email.gr",
                  "(?i-mx:account)" : "12",
                  "(?i-mx:id)" : "1"
                },
                "without_defaults" : false,
                "force" : false
              },
              "browser_cluster" : {
                "wait_for_elements" : {},
                "pool_size" : 6,
                "job_timeout" : 25,
                "worker_time_to_live" : 100,
                "ignore_images" : false,
                "screen_width" : 1600,
                "screen_height" : 1200
              },
              "scope" : {
                "redundant_path_patterns" : {},
                "dom_depth_limit" : 5,
                "exclude_path_patterns" : [],
                "exclude_content_patterns" : [],
                "include_path_patterns" : [],
                "restrict_paths" : [],
                "extend_paths" : [],
                "url_rewrites" : {}
              },
              "session" : {},
              "checks" : [],
              "platforms" : [],
              "plugins" : {},
              "no_fingerprinting" : false,
              "authorized_by" : null
            }
        :return: Perform a new scan
        """
        return self._request("POST", "/scans", data=data)

    def scan_status(self, id):
        """
        Monitor scan progress
        :param id:
        :return:
        """
        return self._request("GET", f"/scans/{id}")

    def scan_summary(self, id):
        """
        Summary
        :param id:
        :return:
        """
        return self._request("GET", f"/scans/{id}/summary")

    def scan_pause(self, id):
        """
        Pause a scan
        :param id:
        :return:
        """

        return self._request("PUT", f"/scans/{id}/pause")

    def scan_resume(self, id):

        """
        :param id:
        :return:
        """
        return self._request("PUT", f"/scans/{id}/resume")

    def scan_xml_report(self, id):
        """
        :return:
        """
        return self._request("GET", f"/scans/{id}/report.xml")

    def stop_scan(self, id):
        """
        Abort or shutdown a scan
        :param id:
        :return:
        """
        return self._request("DELETE", "/scans/%s", id)

    def _request(self, method, url, params=None, headers=None, data=None):
        """Common handler for all the HTTP requests."""
        if not params:
            params = {}

        # set default headers
        if not headers:
            headers = {"accept": "*/*"}
            if method in ["POST", "PUT"]:
                headers["Content-Type"] = "application/json"
        try:
            if self.username_api != "":
                response = requests.request(
                    method=method,
                    url=f'{self.host}:{self.port}{url}',
                    params=params,
                    headers=headers,
                    data=data,
                    auth=(self.username_api, self.password_api),
                )
            else:
                response = requests.request(
                    method=method,
                    url=f'{self.host}:{self.port}{url}',
                    params=params,
                    headers=headers,
                    data=data,
                )
            try:
                response.raise_for_status()

                response_code = response.status_code
                success = response_code // 100 == 2
                if response.text:
                    try:
                        data = response.json()
                    except ValueError:
                        data = response.content
                else:
                    data = ""

                return arachniResponse(
                    success=success, response_code=response_code, data=data
                )
            except ValueError as e:
                return arachniResponse(
                    success=False,
                    message=f"JSON response could not be decoded {e}.",
                )
            except requests.exceptions.HTTPError as e:
                if response.status_code == 400:
                    return arachniResponse(
                        success=False, response_code=400, message="Bad Request"
                    )
                else:
                    return arachniResponse(
                        message=f"There was an error while handling the request. {response.content}",
                        success=False,
                    )
        except Exception as e:
            return arachniResponse(success=False, message=f"Eerror is {e}")


class arachniResponse(object):
    """Container for all arachni REST API response, even errors."""

    def __init__(self, success, message="OK", response_code=-1, data=None):
        self.message = message
        self.success = success
        self.response_code = response_code
        self.data = data

    def __str__(self):
        return str(self.data) if self.data else self.message

    def data_json(self, pintu=False):
        """Returns the data as a valid JSON String."""
        if pintu:
            return json.dumps(
                self.data, sort_keys=True, indent=4, separators=(",", ": ")
            )
        else:
            return json.dumps(self.data)
