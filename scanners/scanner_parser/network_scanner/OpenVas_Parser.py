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

import hashlib
import uuid
from datetime import datetime
from networkscanners.models import (NetworkScanDb, NetworkScanResultsDb)

from dashboard.views import trend_update
from utility.email_notify import email_sch_notify

name = ""
creation_time = ""
modification_time = ""
host = ""
port = ""
threat = ""
severity = ""
description = ""
family = ""
cvss_base = ""
cve = ""
bid = ""
xref = ""
tags = ""
banner = ""
vuln_color = None


def updated_xml_parser(root, project_id, scan_id, username):
    """

    :param root:
    :param project_id:
    :param scan_id:
    :param username:
    :return:
    """
    global host, name, severity, port, threat, creation_time, modification_time, \
        description, family, cvss_base, cve
    for openvas in root.findall(".//result"):
        for r in openvas:
            if r.tag == "description":
                global description
                description = "NA" if r.text is None else r.text
            elif r.tag == "host":
                global host
                host = "NA" if r.text is None else r.text
            elif r.tag == "name":
                global name
                name = "NA" if r.text is None else r.text
            elif r.tag == "port":
                global port
                port = "NA" if r.text is None else r.text
            elif r.tag == "severity":
                global severity
                severity = "NA" if r.text is None else r.text
            elif r.tag == "threat":
                global threat
                threat = "NA" if r.text is None else r.text
        date_time = datetime.now()
        vuln_id = uuid.uuid4()
        dup_data = name + host + severity + port
        duplicate_hash = hashlib.sha256(dup_data.encode("utf-8")).hexdigest()
        match_dup = (
            NetworkScanResultsDb.objects.filter(
                username=username, vuln_duplicate=duplicate_hash
            )
                .values("vuln_duplicate")
                .distinct()
        )
        lenth_match = len(match_dup)
        vuln_color = ""
        if lenth_match == 0:
            duplicate_vuln = "No"
            false_p = NetworkScanResultsDb.objects.filter(
                username=username, false_positive_hash=duplicate_hash
            )
            fp_lenth_match = len(false_p)
            false_positive = "Yes" if fp_lenth_match == 1 else "No"
            if threat == "High":
                vuln_color = "danger"
            elif threat in ["Low", "Log"]:
                vuln_color = "info"
            elif threat == "Medium":
                vuln_color = "warning"
            save_all = NetworkScanResultsDb(
                scan_id=scan_id,
                project_id=project_id,
                vuln_id=vuln_id,
                title=name,
                date_time=date_time,
                severity=threat,
                description=description,
                port=port,
                ip=host,
                vuln_status="Open",
                dup_hash=duplicate_hash,
                vuln_duplicate=duplicate_vuln,
                severity_color=vuln_color,
                false_positive=false_positive,
                scanner='Openvas',
                username=username,
            )
            save_all.save()
        else:
            duplicate_vuln = "Yes"
            all_data_save = NetworkScanResultsDb(
                scan_id=scan_id,
                project_id=project_id,
                vuln_id=vuln_id,
                title=name,
                date_time=date_time,
                severity=threat,
                description=description,
                port=port,
                ip=host,
                false_positive='Duplicate',
                vuln_status="Duplicate",
                dup_hash=duplicate_hash,
                vuln_duplicate=duplicate_vuln,
                severity_color=vuln_color,
                scanner='Openvas',
                username=username,
            )
            all_data_save.save()

        openvas_vul = NetworkScanResultsDb.objects.filter(username=username, scan_id=scan_id, ip=host)
        total_high = len(openvas_vul.filter(severity="High"))
        total_medium = len(openvas_vul.filter(severity="Medium"))
        total_low = len(openvas_vul.filter(severity="Low"))
        total_duplicate = len(openvas_vul.filter(vuln_duplicate="Yes"))
        total_vul = total_high + total_medium + total_low
        NetworkScanDb.objects.filter(username=username, scan_id=scan_id).update(
            total_vul=total_vul,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
            total_dup=total_duplicate,
        )
    trend_update(username=username)
    message = f"OpenVAS Scanner has completed the scan   {scan_id} <br> Total: {total_vul} <br>High: {total_high} <br>Medium: {total_medium} <br>Low {total_low}"

    subject = "Archery Tool Scan Status - OpenVAS Report Uploaded"
    email_sch_notify(subject=subject, message=message)


def get_hosts(root):
    hosts = []
    for openvas in root.findall(".//result"):
        for r in openvas:
            if r.tag == "host":
                global host
                if r.text is None:
                    host = "NA"
                else:
                    host = r.text
                    if host in hosts:
                        print(f"Already present {host}")
                    else:
                        hosts.append(host)
    return hosts