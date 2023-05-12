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
from webscanners.models import WebScansDb, WebScanResultsDb
from utility.email_notify import email_sch_notify

ScanName = None
ScanShortName = None
ScanStartURL = None
ScanStartTime = None
ScanFinishTime = None
ScanScanTime = None
ScanAborted = None
ScanResponsive = None
ScanBanner = None
ScanOs = None
ScanWebServer = None
ScanTechnologies = None
ScanCrawler = None
ScanReportItems = None
VulnName = None
VulnModuleName = None
VulnDetails = None
VulnAffects = None
VulnParameter = None
VulnAOP_SourceFile = None
VulnAOP_SourceLine = None
VulnAOP_Additional = None
VulnIsFalsePositive = None
VulnSeverity = None
VulnType = None
VulnImpact = None
VulnDescription = None
VulnDetailedInformation = None
VulnRecommendation = None
VulnTechnicalDetails = None
VulnCWEList = None
VulnCVEList = None
VulnCVSS = None
VulnCVSS3 = None
VulnReferences = None
vul_col = None
risk = None
UriName = None
VulnUrl = None
FullURL = None


def xml_parser(root, project_id, scan_id, username):
    """

    :param root:
    :param project_id:
    :param scan_id:
    :return:
    """
    date_time = datetime.now()
    global ScanName, ScanShortName, ScanStartURL, ScanStartTime, ScanFinishTime, ScanScanTime, ScanAborted, ScanResponsive, ScanResponsive, ScanBanner, ScanOs, ScanWebServer, ScanTechnologies, ScanCrawler, ScanReportItems, VulnName, VulnModuleName, VulnDetails, VulnAffects, VulnParameter, VulnAOP_SourceFile, VulnAOP_SourceLine, VulnAOP_Additional, VulnIsFalsePositive, VulnSeverity, VulnType, VulnImpact, VulnDescription, VulnDetailedInformation, VulnRecommendation, VulnTechnicalDetails, VulnCWEList, VulnCVEList, VulnCVSS, VulnCVSS3, VulnReferences, vul_col, risk, UriName, VulnUrl, FullURL

    for scan in root:
        for reports in scan:
            if reports.tag == "Name":
                ScanName = reports.text

            if reports.tag == "ShortName":
                ScanShortName = reports.text
            if reports.tag == "StartURL":
                ScanStartURL = reports.text

            if reports.tag == "StartTime":
                ScanStartTime = reports.text
            if reports.tag == "FinishTime":
                ScanFinishTime = reports.text
            if reports.tag == "ScanTime":
                ScanScanTime = reports.text
            if reports.tag == "Aborted":
                ScanAborted = reports.text
            if reports.tag == "Responsive":
                ScanResponsive = reports.text
            if reports.tag == "Banner":
                ScanBanner = reports.text
            if reports.tag == "Os":
                ScanOs = reports.text
            if reports.tag == "WebServer":
                ScanWebServer = reports.text
            if reports.tag == "Technologies":
                ScanTechnologies = reports.text
            if reports.tag == "Crawler":
                ScanCrawler = reports.text
            if reports.tag == "ReportItems":
                ScanReportItems = reports.text
            if reports.tag == "ReportItems":
                ScanReportItems = reports.text
            for report_item in reports:
                for ReportItem in report_item:
                    # print ReportItem
                    # print(ReportItem.tag)

                    if ReportItem.tag == "Name":
                        VulnName = ReportItem.text

                    if ReportItem.tag == "ModuleName":
                        VulnModuleName = ReportItem.text

                    if ReportItem.tag == "Details":
                        VulnDetails = ReportItem.text

                    if ReportItem.tag == "Affects":
                        VulnAffects = ScanStartURL + ReportItem.text

                    if ReportItem.tag == "Parameter":
                        VulnParameter = ReportItem.text

                    if ReportItem.tag == "AOP_SourceFile":
                        VulnAOP_SourceFile = ReportItem.text

                    if ReportItem.tag == "AOP_SourceLine":
                        VulnAOP_SourceLine = ReportItem.text

                    if ReportItem.tag == "AOP_Additional":
                        VulnAOP_Additional = ReportItem.text

                    if ReportItem.tag == "IsFalsePositive":
                        VulnIsFalsePositive = ReportItem.text

                    if ReportItem.tag == "Severity":
                        VulnSeverity = ReportItem.text

                    if ReportItem.tag == "Type":
                        VulnType = ReportItem.text

                    if ReportItem.tag == "Impact":
                        VulnImpact = ReportItem.text

                    if ReportItem.tag == "Description":
                        VulnDescription = ReportItem.text

                    if ReportItem.tag == "DetailedInformation":
                        VulnDetailedInformation = ReportItem.text

                    if ReportItem.tag == "Recommendation":
                        VulnRecommendation = ReportItem.text

                    if ReportItem.tag == "TechnicalDetails":
                        VulnTechnicalDetails = ReportItem.text

                    if ReportItem.tag == "CWEList":
                        VulnCWEList = ReportItem.text

                    if ReportItem.tag == "CVEList":
                        VulnCVEList = ReportItem.text

                    if ReportItem.tag == "CVSS":
                        VulnCVSS = ReportItem.text

                    if ReportItem.tag == "CVSS3":
                        VulnCVSS3 = ReportItem.text

                    if ReportItem.tag == "References":
                        VulnReferences = ReportItem.text

                    if VulnSeverity == "high":
                        vul_col = "danger"
                        risk = "High"
                    elif VulnSeverity == "medium":
                        vul_col = "warning"
                        risk = "Medium"
                    else:
                        vul_col = "info"
                        risk = "Low"
                if VulnName is None:
                    print(VulnName)
                else:
                    for c_url in root.findall(".//SiteFile"):
                        for vuln_url in c_url:
                            if vuln_url.tag == "FullURL":
                                FullURL = vuln_url.text

                            elif vuln_url.tag == "Name":
                                UriName = vuln_url.text
                            elif vuln_url.tag == "URL":
                                VulnUrl = vuln_url.text
                    vuln_id = uuid.uuid4()
                    dup_data = VulnName + FullURL + risk
                    duplicate_hash = hashlib.sha256(
                        dup_data.encode("utf-8")
                    ).hexdigest()

                    match_dup = (
                        WebScanResultsDb.objects.filter(
                            username=username, dup_hash=duplicate_hash
                        )
                        .values("dup_hash")
                        .distinct()
                    )
                    lenth_match = len(match_dup)

                    if lenth_match == 0:
                        duplicate_vuln = "No"

                        false_p = WebScanResultsDb.objects.filter(
                            username=username, false_positive_hash=duplicate_hash
                        )
                        fp_lenth_match = len(false_p)

                        false_positive = "Yes" if fp_lenth_match == 1 else "No"
                        dump_data = WebScanResultsDb(

                            vuln_id=vuln_id,
                            scan_id=scan_id,
                            url=FullURL,
                            title=VulnName,
                            description=str(VulnDescription) + str(VulnDetails) + str(VulnTechnicalDetails),
                            instance=str(VulnParameter) + str(VulnAffects),
                            reference=VulnReferences,
                            project_id=project_id,
                            severity_color=vul_col,
                            severity=risk,
                            date_time=date_time,
                            false_positive=false_positive,
                            vuln_status='Open',
                            dup_hash=duplicate_hash,
                            vuln_duplicate=duplicate_vuln,
                            scanner='Acunetix',
                            username=username,
                        )
                    else:
                        duplicate_vuln = "Yes"

                        dump_data = WebScanResultsDb(
                            vuln_id=vuln_id,
                            scan_id=scan_id,
                            url=VulnUrl,
                            title=VulnName,
                            description=str(VulnDescription) + str(VulnDetails) + str(VulnTechnicalDetails),
                            instance=str(VulnParameter) + str(VulnAffects),
                            reference=VulnReferences,
                            project_id=project_id,
                            severity_color=vul_col,
                            severity=risk,
                            date_time=date_time,
                            false_positive='Duplicate',
                            vuln_status='Duplicate',
                            dup_hash=duplicate_hash,
                            vuln_duplicate=duplicate_vuln,
                            scanner='Acunetix',
                            username=username,
                        )
                    dump_data.save()

    acunetix_all_vul = WebScanResultsDb.objects.filter(
        username=username, scan_id=scan_id, false_positive="No"
    )

    duplicate_count = WebScanResultsDb.objects.filter(
        username=username, scan_id=scan_id, vuln_duplicate="Yes"
    )

    total_high = len(acunetix_all_vul.filter(severity="High"))
    total_medium = len(acunetix_all_vul.filter(severity="Medium"))
    total_low = len(acunetix_all_vul.filter(severity="Low"))
    total_info = len(acunetix_all_vul.filter(severity="Informational"))
    total_duplicate = len(duplicate_count.filter(severity="Yes"))
    total_vul = total_high + total_medium + total_low + total_info

    # cal_total_vuln = total_high + total_medium + total_low + total_info

    WebScansDb.objects.filter(username=username, scan_id=scan_id).update(
        total_vul=total_vul,
        date_time=date_time,
        high_vul=total_high,
        medium_vul=total_medium,
        low_vul=total_low,
        info_vul=total_info,
        total_dup=total_duplicate,
        scan_url=ScanStartURL,
    )
    trend_update(username=username)
    message = f"Acunetix Scanner has completed the scan   {ScanStartURL} <br> Total: {total_vul} <br>High: {total_high} <br>Medium: {total_medium} <br>Low {total_low}"

    subject = "Archery Tool Scan Status - Acunetix Report Uploaded"
    email_sch_notify(subject=subject, message=message)
