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

from dashboard.views import trend_update
from staticscanners.models import StaticScansDb, StaticScanResultsDb
from utility.email_notify import email_sch_notify

scan_id = None
rescan_id = None
scan_date = None
project_id = None
vuln_id = None
source_line = None
line_number = None
code = None
issue_confidence = None
line_range = None
test_id = None
issue_severity = None
issue_text = None
test_name = None
filename = None
more_info = None
vul_col = None
total_vul = ''
total_high = ''
total_medium = ''
total_low = ''


def bandit_report_json(data, project_id, scan_id, username):
    """

    :param data:
    :param project_id:
    :param scan_id:
    :return:
    """
    global vul_col, issue_severity, test_name, filename, line_number, code, issue_confidence, line_range, test_id, issue_text, more_info, total_vul, total_high, total_medium, total_low
    for key, items in data.items():
        if key == "results":
            for res in items:
                for key, value in res.items():
                    if key == "line_number":
                        global line_number
                        line_number = "NA" if value is None else value
                    if key == "code":
                        global code
                        code = "NA" if value is None else value
                    if key == "issue_confidence":
                        global issue_confidence
                        issue_confidence = "NA" if value is None else value
                    if key == "line_range":
                        global line_range
                        line_range = "NA" if value is None else value
                    if key == "test_id":
                        global test_id
                        test_id = "NA" if value is None else value
                    if key == "issue_severity":
                        global issue_severity
                        issue_severity = "NA" if value is None else value
                    if key == "issue_text":
                        global issue_text
                        issue_text = "NA" if value is None else value
                    if key == "test_name":
                        global test_name
                        test_name = "NA" if value is None else value
                    if key == "filename":
                        global filename
                        filename = "NA" if value is None else value
                    if key == "more_info":
                        global more_info
                        more_info = "NA" if value is None else value
                date_time = datetime.now()
                vul_id = uuid.uuid4()

                if issue_severity == "HIGH":
                    vul_col = "danger"
                    issue_severity = 'High'

                elif issue_severity == "MEDIUM":
                    vul_col = "warning"
                    issue_severity = 'Medium'

                elif issue_severity == "LOW":
                    vul_col = "info"
                    issue_severity = 'Low'

                dup_data = test_name + filename + issue_severity
                duplicate_hash = hashlib.sha256(dup_data.encode("utf-8")).hexdigest()

                match_dup = (
                    StaticScanResultsDb.objects.filter(
                        username=username, dup_hash=duplicate_hash
                    )
                    .values("dup_hash")
                    .distinct()
                )
                lenth_match = len(match_dup)

                if lenth_match == 0:
                    duplicate_vuln = "No"

                    false_p = StaticScanResultsDb.objects.filter(
                        username=username, false_positive_hash=duplicate_hash
                    )
                    fp_lenth_match = len(false_p)

                    false_positive = "Yes" if fp_lenth_match == 1 else "No"
                    save_all = StaticScanResultsDb(
                        scan_id=scan_id,
                        date_time=date_time,
                        project_id=project_id,
                        vuln_id=vul_id,
                        severity=issue_severity,
                        title=test_name,
                        fileName=filename,
                        description=str(issue_text) + '\n\n' + str(code) + '\n\n' + str(line_range),
                        references=more_info,
                        severity_color=vul_col,
                        false_positive=false_positive,
                        vuln_status="Open",
                        dup_hash=duplicate_hash,
                        vuln_duplicate=duplicate_vuln,
                        username=username,
                        scanner='Bandit',
                    )
                else:
                    duplicate_vuln = "Yes"

                    save_all = StaticScanResultsDb(
                        scan_id=scan_id,
                        date_time=date_time,
                        project_id=project_id,
                        vuln_id=vul_id,
                        severity=issue_severity,
                        title=test_name,
                        fileName=filename,
                        description=str(issue_text) + '\n\n' + str(code) + '\n\n' + str(line_range),
                        references=more_info,
                        severity_color=vul_col,
                        false_positive="Duplicate",
                        vuln_status="Duplicate",
                        dup_hash=duplicate_hash,
                        vuln_duplicate=duplicate_vuln,
                        username=username,
                        scanner='Bandit',

                    )
                save_all.save()

        all_bandit_data = StaticScanResultsDb.objects.filter(
            username=username, scan_id=scan_id, false_positive="No"
        )

        duplicate_count = StaticScanResultsDb.objects.filter(
            username=username, scan_id=scan_id, vuln_duplicate="Yes"
        )

        total_vul = len(all_bandit_data)
        total_high = len(all_bandit_data.filter(severity="High"))
        total_medium = len(all_bandit_data.filter(severity="Medium"))
        total_low = len(all_bandit_data.filter(severity="Low"))
        total_duplicate = len(duplicate_count.filter(vuln_duplicate="Yes"))

        StaticScansDb.objects.filter(username=username, scan_id=scan_id).update(
            total_vul=total_vul,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
            total_dup=total_duplicate,
        )
    trend_update(username=username)
    message = f"Bandit Scanner has completed the scan   {scan_id} <br> Total: {total_vul} <br>High: {total_high} <br>Medium: {total_medium} <br>Low {total_low}"

    subject = "Archery Tool Scan Status - Bandit Report Uploaded"
    email_sch_notify(subject=subject, message=message)
