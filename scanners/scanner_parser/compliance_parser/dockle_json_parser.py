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


import uuid

from compliance.models import dockle_scan_db, dockle_scan_results_db
from utility.email_notify import email_sch_notify

status = None
controls_results_message = None
vuln_col = ""


def dockle_report_json(data, project_id, scan_id, username):
    """

    :param data:
    :param project_id:
    :param scan_id:
    :return:
    """
    global vul_col

    for vuln in data["details"]:
        code = vuln["code"]
        title = vuln["title"]
        level = vuln["level"]
        alerts = vuln["alerts"][0]

        if level == "FATAL":
            vul_col = "danger"

        elif level == "INFO":
            vul_col = "info"

        elif level in ["PASS", "WARN"]:
            vul_col = "warning"

        vul_id = uuid.uuid4()

        save_all = dockle_scan_results_db(
            scan_id=scan_id,
            project_id=project_id,
            vul_col=vul_col,
            vuln_id=vul_id,
            code=code,
            title=title,
            alerts=alerts,
            level=level,
            username=username,
        )
        save_all.save()

    all_dockle_data = dockle_scan_results_db.objects.filter(
        username=username, scan_id=scan_id
    )

    total_vul = len(all_dockle_data)
    dockle_failed = len(all_dockle_data.filter(level="FATAL"))
    dockle_passed = len(all_dockle_data.filter(level="PASS"))
    dockle_warn = len(all_dockle_data.filter(level="WARN"))
    dockle_info = len(all_dockle_data.filter(level="INFO"))
    total_duplicate = len(all_dockle_data.filter(level="Yes"))

    dockle_scan_db.objects.filter(username=username, scan_id=scan_id).update(
        total_vuln=total_vul,
        dockle_fatal=dockle_failed,
        dockle_warn=dockle_warn,
        dockle_info=dockle_info,
        dockle_pass=dockle_passed,
        total_dup=total_duplicate,
    )
    message = f"dockle Scanner has completed the scan   {scan_id} <br> Total: {total_vul} <br>Failed: {dockle_failed} <br>failed: {dockle_warn} <br>Skipped {dockle_passed}"

    subject = "Archery Tool Scan Status - dockle Report Uploaded"
    email_sch_notify(subject=subject, message=message)
