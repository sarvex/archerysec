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

# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.core import signing
from django.shortcuts import HttpResponseRedirect, render
from django.urls import reverse
from jira import JIRA
from notifications.signals import notify

from jiraticketing.models import jirasetting
from networkscanners.models import NetworkScanResultsDb
from webscanners.models import (WebScanResultsDb)
from archerysettings.models import settings_db
import uuid

jira_url = ""
j_username = ""

password = ""
jira_projects = ""


def jira_setting(request):
    """

    :param request:
    :return:
    """
    setting_id = uuid.uuid4()
    username = request.user.username
    all_jira_settings = jirasetting.objects.filter(username=username)
    for jira in all_jira_settings:
        global jira_url, j_username, password
        jira_url = jira.jira_server
        j_username = signing.loads(jira.jira_username)
        password = signing.loads(jira.jira_password)
    jira_server = jira_url
    jira_username = j_username
    jira_password = password

    if request.method == "POST":
        jira_url = request.POST.get("jira_url")
        jira_username = request.POST.get("jira_username")
        jira_password = request.POST.get("jira_password")

        j_username = signing.dumps(jira_username)
        password = signing.dumps(jira_password)

        setting_dat = settings_db(
            username=username,
            setting_id=setting_id,
            setting_scanner='Jira',
        )
        setting_dat.save()

        save_data = jirasetting(
            setting_id=setting_id,
            username=username,
            jira_server=jira_url,
            jira_username=j_username,
            jira_password=password,
        )
        save_data.save()

        options = {"server": jira_server}
        try:

            jira_ser = JIRA(
                options, basic_auth=(jira_username, jira_password), timeout=5
            )
            jira_projects = jira_ser.projects()
            print(len(jira_projects))
            jira_info = True
            settings_db.objects.filter(setting_id=setting_id).update(
                setting_status=jira_info
            )
        except Exception as e:
            print(e)
            jira_info = False
            settings_db.objects.filter(setting_id=setting_id).update(
                setting_status=jira_info
            )

        return HttpResponseRedirect(reverse("archerysettings:settings"))

    return render(
        request,
        "jiraticketing/jira_setting_form.html",
        {
            "jira_server": jira_server,
            "jira_username": jira_username,
            "jira_password": jira_password,
        },
    )


def submit_jira_ticket(request):
    global jira_projects, jira_ser
    r_username = request.user.username
    jira_setting = jirasetting.objects.filter(username=r_username)
    user = request.user

    for jira in jira_setting:
        jira_url = jira.jira_server
        username = jira.jira_username
        password = jira.jira_password
    jira_server = jira_url
    jira_username = signing.loads(username)
    jira_password = signing.loads(password)

    options = {"server": jira_server}
    try:
        jira_ser = JIRA(options, basic_auth=(jira_username, jira_password))
        jira_projects = jira_ser.projects()
    except Exception as e:
        print(e)
        notify.send(user, recipient=user, verb="Jira settings not found")

    if request.method == "GET":
        summary = request.GET["summary"]
        description = request.GET["description"]
        scanner = request.GET["scanner"]
        vuln_id = request.GET["vuln_id"]
        scan_id = request.GET["scan_id"]

        return render(
            request,
            "jiraticketing/submit_jira_ticket.html",
            {
                "jira_projects": jira_projects,
                "summary": summary,
                "description": description,
                "scanner": scanner,
                "vuln_id": vuln_id,
                "scan_id": scan_id,
            },
        )

    if request.method == "POST":
        summary = request.POST.get("summary")
        description = request.POST.get("description")
        project_id = request.POST.get("project_id")
        issue_type = request.POST.get("issue_type")
        vuln_id = request.POST.get("vuln_id")
        scanner = request.POST.get("scanner")
        scan_id = request.POST.get("scan_id")

        issue_dict = {
            "project": {"id": project_id},
            "summary": summary,
            "description": description,
            "issuetype": {"name": issue_type},
        }
        new_issue = jira_ser.create_issue(fields=issue_dict)
        print(new_issue)

        if scanner == "zap":
            WebScanResultsDb.objects.filter(
                username=r_username, vuln_id=vuln_id, scanner='zap'
            ).update(jira_ticket=new_issue)
            return HttpResponseRedirect(
                (
                    reverse("zapscanner:zap_vuln_details")
                    + f"?scan_id={scan_id}&scan_name={summary}"
                )
            )
        elif scanner == "burp":
            WebScanResultsDb.objects.filter(
                username=r_username, vuln_id=vuln_id, scanner='Burp'
            ).update(jira_ticket=new_issue)
            return HttpResponseRedirect(
                (
                    reverse("burpscanner:burp_vuln_out")
                    + f"?scan_id={scan_id}&scan_name={summary}"
                )
            )
        elif scanner == "arachni":
            WebScanResultsDb.objects.filter(
                username=r_username, vuln_id=vuln_id, scanner='Arachni'
            ).update(jira_ticket=new_issue)
            return HttpResponseRedirect(
                (
                    reverse("arachniscanner:arachni_vuln_out")
                    + f"?scan_id={scan_id}&scan_name={summary}"
                )
            )

        elif scanner == "netsparker":
            WebScanResultsDb.objects.filter(
                username=r_username, vuln_id=vuln_id, scanner='Netsparker'
            ).update(jira_ticket=new_issue)
            return HttpResponseRedirect(
                (
                    reverse("netsparkerscanner:netsparker_vuln_out")
                    + f"?scan_id={scan_id}&scan_name={summary}"
                )
            )

        elif scanner == "webinspect":
            WebScanResultsDb.objects.filter(
                username=r_username, vuln_id=vuln_id, scanner='Webinspect'
            ).update(jira_ticket=new_issue)
            return HttpResponseRedirect(
                (
                    reverse("webinspectscanner:webinspect_vuln_out")
                    + f"?scan_id={scan_id}&scan_name={summary}"
                )
            )

        elif scanner == "acunetix":
            WebScanResultsDb.objects.filter(
                username=r_username, vuln_id=vuln_id, scanner='Acunetix'
            ).update(jira_ticket=new_issue)
            return HttpResponseRedirect(
                (
                    reverse("acunetixscanner:acunetix_vuln_out")
                    + f"?scan_id={scan_id}&scan_name={summary}"
                )
            )

        elif scanner == "open_vas":
            NetworkScanResultsDb.objects.filter(
                username=r_username, vul_id=vuln_id
            ).update(jira_ticket=new_issue)
            return HttpResponseRedirect(
                reverse("networkscanners:vul_details") + f"?scan_id={scan_id}"
            )
        elif scanner == "nessus":
            NetworkScanResultsDb.objects.filter(username=r_username, vul_id=vuln_id).update(
                jira_ticket=new_issue
            )
            return HttpResponseRedirect(
                reverse("networkscanners:nessus_vuln_details")
                + f"?scan_id={scan_id}"
            )
