# -*- coding: utf-8 -*-
#                    _
#     /\            | |
#    /  \   _ __ ___| |__   ___ _ __ _   _
#   / /\ \ | '__/ __| '_ \ / _ \ '__| | | |
#  / ____ \| | | (__| | | |  __/ |  | |_| |
# /_/    \_\_|  \___|_| |_|\___|_|   \__, |
#                                     __/ |
#                                    |___/
# Copyright (C) 2017 Anand Tiwari
#
# Email:   anandtiwarics@gmail.com
# Twitter: @anandtiwarics
#
# This file is part of ArcherySec Project.

import base64
import hashlib
import uuid
from datetime import datetime

from django.shortcuts import HttpResponse

from dashboard.views import trend_update
# from django.core.mail import send_mail
from webscanners import email_notification
from webscanners.models import (WebScansDb,
                                WebScanResultsDb)
from utility.email_notify import email_sch_notify

project_id = None
target_url = None
scan_ip = None
burp_status = 0
serialNumber = ""
types = ""
name = ""
host = ""
path = ""
location = ""
severity = ""
confidence = ""
issueBackground = ""
remediationBackground = ""
references = ""
vulnerabilityClassifications = ""
issueDetail = ""
requestresponse = ""
vuln_id = ""
methods = ""
request_datas = ""
response_datas = ""
vul_col = ""
false_positive = None
issue_description = ""
issue_remediation = ""
issue_reference = ""
issue_vulnerability_classifications = ""
url = ""


def burp_scan_data(root, project_id, scan_id, username):
    date_time = datetime.now()
    """
    The function parse the burp result as xml data
    and stored into archery database.
    :param xml_data:
    :return:
    """
    global vuln_id, burp_status, vul_col, issue_description, issue_remediation, issue_reference, issue_vulnerability_classifications, vul_col, severity, name, path, host, location, confidence, types, serialNumber, request_datas, response_datas, url
    for issue in root:
        for data in issue:
            vuln_id = uuid.uuid4()
            if data.tag == "name":
                global name
                name = "NA" if data.text is None else data.text
            if data.tag == "host":
                global host
                host = "NA" if data.text is None else data.text
            if data.tag == "path":
                global path
                path = "NA" if data.text is None else data.text
            if data.tag == "location":
                global location
                location = "NA" if data.text is None else data.text
            if data.tag == "severity":
                global severity
                severity = "NA" if data.text is None else data.text
            if data.tag == "requestresponse":
                global requestresponse
                requestresponse = "NA" if data.text is None else data.text
                for d in data:
                    req = d.tag
                    met = d.attrib
                    if req == "request":
                        global request_datas
                        reqst = d.text
                        request_datas = base64.b64decode(reqst)  # reqst

                    elif req == "response":
                        global response_datas
                        res_dat = d.text
                        response_datas = base64.b64decode(res_dat)  # res_dat

                    for key, items in met.items():
                        global methods
                        if key == "method":
                            methods = items

            if data.tag == "issueBackground":
                global issue_description
                issue_description = "NA" if data.text is None else data.text
            if data.tag == "remediationBackground":
                global issue_remediation
                issue_remediation = "NA" if data.text is None else data.text
            if data.tag == "references":
                global issue_reference
                issue_reference = "NA" if data.text is None else data.text
            if data.tag == "vulnerabilityClassifications":
                global issue_vulnerability_classifications
                issue_vulnerability_classifications = "NA" if data.text is None else data.text
        details = (
            str(issue_description)
            + '\n'
            + str(request_datas)
            + '\n\n'
            + str(response_datas)
            + '\n\n'
            + '\n\n'
            + str(issue_description)
            + '\n\n'
            + str(issue_vulnerability_classifications)
        )

        if severity == "High":
            vul_col = "danger"
        elif severity == "Medium":
            vul_col = "warning"
        elif severity == "Low":
            vul_col = "info"
        else:
            severity = "Low"
            vul_col = "info"

        vuln_id = uuid.uuid4()

        dup_data = name + host + location + details + severity
        duplicate_hash = hashlib.sha256(dup_data.encode("utf-8")).hexdigest()

        match_dup = (
            WebScanResultsDb.objects.filter(
                username=username, dup_hash=duplicate_hash, scanner='Burp'
            )
                .values("dup_hash")
                .distinct()
        )
        lenth_match = len(match_dup)

        if lenth_match == 0:
            duplicate_vuln = "No"

            false_p = WebScanResultsDb.objects.filter(
                username=username, false_positive_hash=duplicate_hash, scanner='Burp'
            )
            fp_lenth_match = len(false_p)

            global false_positive
            false_positive = "Yes" if fp_lenth_match == 1 else "No"
            url = host + location

            try:
                data_dump = WebScanResultsDb(
                    scan_id=scan_id,
                    vuln_id=vuln_id,
                    url=url,
                    title=name,
                    solution=issue_remediation,
                    description=details,
                    reference=issue_reference,
                    project_id=project_id,
                    severity_color=vul_col,
                    severity=severity,
                    date_time=date_time,
                    false_positive=false_positive,
                    vuln_status="Open",
                    dup_hash=duplicate_hash,
                    vuln_duplicate=duplicate_vuln,
                    scanner='Burp',
                    username=username,
                )
                data_dump.save()
            except Exception as e:
                print(e)

        else:
            duplicate_vuln = "Yes"

            try:
                data_dump = WebScanResultsDb(
                    scan_id=scan_id,
                    vuln_id=vuln_id,
                    url=url,
                    title=name,
                    solution=issue_remediation,
                    description=issue_description,
                    reference=issue_reference,
                    project_id=project_id,
                    severity_color=vul_col,
                    severity=severity,
                    date_time=date_time,
                    false_positive="Duplicate",
                    vuln_status="Duplicate",
                    dup_hash=duplicate_hash,
                    vuln_duplicate=duplicate_vuln,
                    scanner='Burp',
                    username=username
                )
                data_dump.save()
            except Exception as e:
                print(e)

    burp_all_vul = WebScanResultsDb.objects.filter(
        username=username, scan_id=scan_id, scanner='Burp', false_positive="No"
    )

    duplicate_count = WebScanResultsDb.objects.filter(
        username=username, scan_id=scan_id, scanner='Burp', vuln_duplicate="Yes"
    )

    total_vul = len(burp_all_vul)
    total_high = len(burp_all_vul.filter(severity="High"))
    total_medium = len(burp_all_vul.filter(severity="Medium"))
    total_low = len(burp_all_vul.filter(severity="Low"))
    total_info = len(burp_all_vul.filter(severity="Information"))
    total_duplicate = len(duplicate_count.filter(vuln_duplicate="Yes"))
    WebScansDb.objects.filter(username=username, scan_id=scan_id, scanner='Burp').update(
        scan_url=host,
        date_time=date_time,
        total_vul=total_vul,
        high_vul=total_high,
        medium_vul=total_medium,
        low_vul=total_low,
        info_vul=total_info,
        total_dup=total_duplicate,
    )
    print(host)
    trend_update(username=username)
    message = f"Burp Scanner has completed the scan   {host} <br> Total: {total_vul} <br>High: {total_high} <br>Medium: {total_medium} <br>Low {total_low}"

    subject = "Archery Tool Scan Status - Burp Report Uploaded"
    email_sch_notify(subject=subject, message=message)

    try:
        email_notification.email_notify()
    except Exception as e:
        print(e)
    HttpResponse(status=201)
