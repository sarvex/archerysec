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


""" Author: Anand Tiwari """

from __future__ import unicode_literals

import datetime
from itertools import chain

from django.contrib.auth import user_logged_in
from django.contrib.auth.models import User
from django.db.models import Sum
from django.shortcuts import HttpResponse, HttpResponseRedirect, render
from django.urls import reverse
from notifications.models import Notification

from compliance.models import dockle_scan_db, inspec_scan_db
from dashboard.scans_data import scans_query
from manual_scan.models import manual_scan_results_db, manual_scans_db
from projects.models import Month, MonthSqlite, month_db, project_db
from staticscanners.models import (StaticScanResultsDb, StaticScansDb)
from webscanners.models import (WebScanResultsDb, WebScansDb)
from networkscanners.models import (NetworkScanResultsDb, NetworkScanDb)
from webscanners.resources import AllResource

# Create your views here.
chart = []
all_high_stat = ""
data = ""


def trend_update(username):
    current_month = ''

    all_project = project_db.objects.filter(username=username)

    for project in all_project:
        proj_id = project.project_id
        all_date_data = (project_db.objects
                         .annotate(month=Month('date_time'))
                         .values('month').annotate(total_high=Sum('total_high')).annotate(
            total_medium=Sum('total_medium')).annotate(total_low=Sum('total_low')).order_by("month")
                         )

        try:
            high = all_date_data.first()['total_high']
            medium = all_date_data.first()['total_medium']
            low = all_date_data.first()['total_low']
        except:
            all_date_data = (project_db.objects
                             .annotate(month=MonthSqlite('date_time'))
                             .values('month').annotate(total_high=Sum('total_high')).annotate(
                total_medium=Sum('total_medium')).annotate(total_low=Sum('total_low')).order_by("month")
                             )
            high = all_date_data.first()['total_high']
            medium = all_date_data.first()['total_medium']
            low = all_date_data.first()['total_low']

        all_month_data_display = month_db.objects.filter(username=username)

        if len(all_month_data_display) == 0:
            add_data = month_db(username=username, project_id=proj_id, month=current_month, high=high, medium=medium,
                                low=low)
            add_data.save()

        for data in all_month_data_display:
            current_month = datetime.datetime.now().month
            if current_month == 1:
                month_db.objects.filter(username=username, project_id=proj_id, month='2').delete()
                month_db.objects.filter(username=username, project_id=proj_id, month='3').delete()
                month_db.objects.filter(username=username, project_id=proj_id, month='4').delete()
                month_db.objects.filter(username=username, project_id=proj_id, month='5').delete()
                month_db.objects.filter(username=username, project_id=proj_id, month='6').delete()
                month_db.objects.filter(username=username, project_id=proj_id, month='7').delete()
                month_db.objects.filter(username=username, project_id=proj_id, month='8').delete()
                month_db.objects.filter(username=username, project_id=proj_id, month='9').delete()
                month_db.objects.filter(username=username, project_id=proj_id, month='10').delete()
                month_db.objects.filter(username=username, project_id=proj_id, month='11').delete()
                month_db.objects.filter(username=username, project_id=proj_id, month='12').delete()

            match_data = month_db.objects.filter(username=username, project_id=proj_id, month=current_month)
            if len(match_data) == 0:
                add_data = month_db(username=username, project_id=proj_id, month=current_month, high=high,
                                    medium=medium, low=low)
                add_data.save()

            elif int(data.month) == current_month:
                month_db.objects.filter(username=username, project_id=proj_id, month=current_month).update(high=high,
                                                                                                           medium=medium,
                                                                                                           low=low)

        total_vuln = scans_query.all_vuln(username=username, project_id=proj_id, query='total')
        total_high = scans_query.all_vuln(username=username, project_id=proj_id, query='high')
        total_medium = scans_query.all_vuln(username=username, project_id=proj_id, query='medium')
        total_low = scans_query.all_vuln(username=username, project_id=proj_id, query='low')

        total_open = scans_query.all_vuln_count_data(username=username, project_id=proj_id, query='Open')
        total_close = scans_query.all_vuln_count_data(username=username, project_id=proj_id, query='Closed')
        total_false = scans_query.all_vuln_count_data(username=username, project_id=proj_id, query='false')

        total_net = scans_query.all_net(username=username, project_id=proj_id, query='total')
        total_web = scans_query.all_web(username=username, project_id=proj_id, query='total')
        total_static = scans_query.all_static(username=username, project_id=proj_id, query='total')

        high_net = scans_query.all_net(username, proj_id, query='high')
        high_web = scans_query.all_web(username, proj_id, query='high')
        high_static = scans_query.all_static(username, proj_id, query='high')

        medium_net = scans_query.all_net(username, proj_id, query='medium')
        medium_web = scans_query.all_web(username, proj_id, query='medium')
        medium_static = scans_query.all_static(username, proj_id, query='medium')

        low_net = scans_query.all_net(username, proj_id, query='low')
        low_web = scans_query.all_web(username, proj_id, query='low')
        low_static = scans_query.all_static(username, proj_id, query='low')

        project_db.objects.filter(username=username,
                                  project_id=proj_id
                                  ).update(total_vuln=total_vuln,
                                           total_open=total_open,
                                           total_close=total_close,
                                           total_false=total_false,
                                           total_net=total_net,
                                           total_web=total_web,
                                           total_static=total_static,
                                           total_high=total_high,
                                           total_medium=total_medium,
                                           total_low=total_low,
                                           high_net=high_net,
                                           high_web=high_web,
                                           high_static=high_static,
                                           medium_net=medium_net,
                                           medium_web=medium_web,
                                           medium_static=medium_static,
                                           low_net=low_net,
                                           low_web=low_web,
                                           low_static=low_static,
                                           )


def dashboard(request):
    """
    The function calling Project Dashboard page.
    :param request:
    :return:
    """

    scanners = 'vscanners'
    username = request.user.username

    trend_update(username=username)

    all_project = project_db.objects.filter(username=username)

    current_year = datetime.datetime.now().year

    user = user_logged_in
    all_notify = Notification.objects.unread()

    all_month_data_display = month_db.objects.filter(username=username).values('month', 'high', 'medium',
                                                                               'low').distinct()

    return render(request,
                  'dashboard/index.html',
                  {'all_project': all_project,
                   'scanners': scanners,
                   'total_count_project': project_db.objects.filter(username=username).aggregate(Sum('total_vuln')),
                   'open_count_project': project_db.objects.filter(username=username).aggregate(Sum('total_open')),
                   'close_count_project': project_db.objects.filter(username=username).aggregate(Sum('total_close')),
                   'false_count_project': project_db.objects.filter(username=username).aggregate(Sum('total_false')),
                   'net_count_project': project_db.objects.filter(username=username).aggregate(Sum('total_net')),
                   'web_count_project': project_db.objects.filter(username=username).aggregate(Sum('total_web')),
                   'static_count_project': project_db.objects.filter(username=username).aggregate(Sum('total_static')),
                   'high_count_project': project_db.objects.filter(username=username).aggregate(Sum('total_high')),
                   'medium_count_project': project_db.objects.filter(username=username).aggregate(Sum('total_medium')),
                   'low_count_project': project_db.objects.filter(username=username).aggregate(Sum('total_low')),
                   'high_net_count_project': project_db.objects.filter(username=username).aggregate(Sum('high_net')),
                   'high_web_count_project': project_db.objects.filter(username=username).aggregate(Sum('high_web')),
                   'high_static_count_project': project_db.objects.filter(username=username).aggregate(
                       Sum('high_static')),
                   'medium_net_count_project': project_db.objects.filter(username=username).aggregate(
                       Sum('medium_net')),
                   'medium_web_count_project': project_db.objects.filter(username=username).aggregate(
                       Sum('medium_web')),
                   'medium_static_count_project': project_db.objects.filter(username=username).aggregate(
                       Sum('medium_static')),
                   'low_net_count_project': project_db.objects.filter(username=username).aggregate(Sum('low_net')),
                   'low_web_count_project': project_db.objects.filter(username=username).aggregate(Sum('low_web')),
                   'low_static_count_project': project_db.objects.filter(username=username).aggregate(
                       Sum('low_static')),
                   'all_month_data_display': all_month_data_display,
                   'current_year': current_year,
                   'message': all_notify
                   })


def project_dashboard(request):
    """
    The function calling Project Dashboard page.
    :param request:
    :return:
    """

    scanners = 'vscanners'
    username = request.user.username
    all_project = project_db.objects.filter(username=username)

    all_notify = Notification.objects.unread()

    return render(request,
                  'dashboard/project.html',
                  {'all_project': all_project,
                   'scanners': scanners,
                   'message': all_notify
                   })


def proj_data(request):
    """
    The function pulling all project data from database.
    :param request:
    :return:
    """
    username = request.user.username
    all_project = project_db.objects.filter(username=username)
    project_id = request.GET['project_id'] if request.GET['project_id'] else ''
    project_dat = project_db.objects.filter(username=username, project_id=project_id)
    web_scan_dat = WebScansDb.objects.filter(username=username, project_id=project_id)
    static_scan = StaticScansDb.objects.filter(username=username, project_id=project_id)
    network_dat = NetworkScanDb.objects.filter(username=username, project_id=project_id)
    inspec_dat = inspec_scan_db.objects.filter(username=username, project_id=project_id)
    dockle_dat = dockle_scan_db.objects.filter(username=username, project_id=project_id)
    compliance_dat = chain(inspec_dat, dockle_dat)
    all_comp_inspec = inspec_scan_db.objects.filter(username=username, project_id=project_id)

    all_comp_dockle = inspec_scan_db.objects.filter(username=username, project_id=project_id)

    all_compliance_seg = chain(all_comp_inspec, all_comp_dockle)

    pentest = manual_scans_db.objects.filter(username=username, project_id=project_id)

    all_notify = Notification.objects.unread()

    all_high = scans_query.all_vuln(username=username, project_id=project_id, query='high')
    all_medium = scans_query.all_vuln(username=username, project_id=project_id, query='medium')
    all_low = scans_query.all_vuln(username=username, project_id=project_id, query='low')

    total = all_high, all_medium, all_low

    tota_vuln = sum(total)

    return render(request,
                  'dashboard/project.html',
                  {'project_id': project_id,
                   'tota_vuln': tota_vuln,
                   'all_vuln': scans_query.all_vuln(username=username, project_id=project_id, query='total'),
                   'total_web': scans_query.all_web(username=username, project_id=project_id, query='total'),
                   'total_static': scans_query.all_static(username=username, project_id=project_id, query='total'),
                   'total_network': scans_query.all_net(username=username, project_id=project_id, query='total'),
                   'all_high': all_high,
                   'all_medium': all_medium,
                   'all_low': all_low,
                   'all_web_high': scans_query.all_web(username=username, project_id=project_id, query='high'),
                   'all_web_medium': scans_query.all_web(username=username, project_id=project_id, query='medium'),
                   'all_network_medium': scans_query.all_net(username=username, project_id=project_id, query='medium'),
                   'all_network_high': scans_query.all_net(username=username, project_id=project_id, query='high'),
                   'all_web_low': scans_query.all_web(username=username, project_id=project_id, query='low'),
                   'all_network_low': scans_query.all_net(username=username, project_id=project_id, query='low'),
                   'all_project': all_project,
                   'project_dat': project_dat,
                   'web_scan_dat': web_scan_dat,
                   'all_static_high': scans_query.all_static(username=username, project_id=project_id, query='high'),
                   'all_static_medium': scans_query.all_static(username=username, project_id=project_id,
                                                               query='medium'),
                   'all_static_low': scans_query.all_static(username=username, project_id=project_id, query='low'),
                   'static_scan': static_scan,
                   'pentest': pentest,
                   'network_dat': network_dat,
                   'all_compliance_failed': scans_query.all_compliance(username=username, project_id=project_id,
                                                                       query='failed'),
                   'all_compliance_passed': scans_query.all_compliance(username=username, project_id=project_id,
                                                                       query='passed'),
                   'all_compliance_skipped': scans_query.all_compliance(username=username, project_id=project_id,
                                                                        query='skipped'),
                   'total_compliance': scans_query.all_compliance(username=username, project_id=project_id,
                                                                  query='total'),
                   'all_compliance': all_compliance_seg,

                   'compliance_dat': compliance_dat,
                   'inspec_dat': inspec_dat,
                   'dockle_dat': dockle_dat,
                   'all_closed_vuln': scans_query.all_vuln_count_data(username, project_id, query='Closed'),
                   'all_false_positive': scans_query.all_vuln_count_data(username, project_id, query='false'),
                   'message': all_notify
                   })


def all_high_vuln(request):
    # add your scanner gloabl variable <scannername>
    web_all_high = ''
    sast_all_high = ''
    net_all_high = ''
    pentest_all_high = ''

    username = request.user.username
    all_notify = Notification.objects.unread()
    if request.GET['project_id']:
        project_id = request.GET['project_id']
        severity = request.GET['severity']
    else:
        project_id = ''
        severity = ''
    if severity == 'All':
        web_all_high = WebScanResultsDb.objects.filter(username=username, false_positive='No')
        sast_all_high = StaticScanResultsDb.objects.filter(username=username, false_positive='No')
        net_all_high = NetworkScanResultsDb.objects.filter(username=username, false_positive='No')
        pentest_all_high = manual_scan_results_db.objects.filter(username=username)

    elif severity == 'All_Closed':
        web_all_high = WebScanResultsDb.objects.filter(username=username, vuln_status='Closed')
        sast_all_high = StaticScanResultsDb.objects.filter(username=username, vuln_status='Closed')
        net_all_high = NetworkScanResultsDb.objects.filter(username=username, vuln_status='Closed')
        pentest_all_high = manual_scan_results_db.objects.filter(username=username)

    elif severity == 'All_False_Positive':
        web_all_high = WebScanResultsDb.objects.filter(username=username, false_positive='Yes')
        sast_all_high = StaticScanResultsDb.objects.filter(username=username, false_positive='Yes')
        net_all_high = NetworkScanResultsDb.objects.filter(username=username, false_positive='Yes')
        pentest_all_high = manual_scan_results_db.objects.filter(username=username)

    elif severity == 'Close':
        # add your scanner name here <scannername>
        web_all_high = WebScanResultsDb.objects.filter(username=username,
                                                       project_id=project_id,
                                                       vuln_status='Closed')
        sast_all_high = StaticScanResultsDb.objects.filter(username=username,
                                                           project_id=project_id,
                                                           vuln_status='Closed')
        net_all_high = NetworkScanResultsDb.objects.filter(username=username,
                                                              project_id=project_id,
                                                              vuln_status='Closed')

        pentest_all_high = manual_scan_results_db.objects.filter(username=username,
                                                                 project_id=project_id,

                                                                 vuln_status='Closed')

    elif severity == 'False':
        # add your scanner name here <scannername>
        web_all_high = WebScanResultsDb.objects.filter(username=username,
                                                       project_id=project_id,
                                                       false_positive='Yes')
        sast_all_high = StaticScanResultsDb.objects.filter(username=username,
                                                           project_id=project_id,
                                                           false_positive='Yes')
        net_all_high = NetworkScanResultsDb.objects.filter(username=username,
                                                              project_id=project_id,
                                                              false_positive='Yes')

        pentest_all_high = ''

    elif severity == 'High':
        # add your scanner name here <scannername>

        web_all_high = WebScanResultsDb.objects.filter(username=username,
                                                       project_id=project_id,
                                                       severity='High',
                                                       false_positive='No')
        sast_all_high = StaticScanResultsDb.objects.filter(username=username,
                                                           project_id=project_id,
                                                           severity='High',
                                                           false_positive='No')
        net_all_high = NetworkScanResultsDb.objects.filter(username=username,
                                                           project_id=project_id,
                                                           severity='High',
                                                           false_positive='No')

        pentest_all_high = manual_scan_results_db.objects.filter(username=username,
                                                                 severity='High',
                                                                 project_id=project_id)

    elif severity == 'Low':
        # add your scanner name here <scannername>

        web_all_high = WebScanResultsDb.objects.filter(username=username,
                                                       project_id=project_id,
                                                       severity='Low')
        sast_all_high = StaticScanResultsDb.objects.filter(username=username,
                                                           project_id=project_id,
                                                           severity='Low')
        net_all_high = NetworkScanResultsDb.objects.filter(username=username,
                                                           project_id=project_id,
                                                           severity='Low')

        pentest_all_high = manual_scan_results_db.objects.filter(username=username,
                                                                 severity='Low',
                                                                 project_id=project_id)

    elif severity == 'Medium':
        # All Medium

        # add your scanner name here <scannername>

        web_all_high = WebScanResultsDb.objects.filter(username=username,
                                                       project_id=project_id,
                                                       severity='Medium')
        sast_all_high = StaticScanResultsDb.objects.filter(username=username,
                                                           project_id=project_id,
                                                           severity='Medium')
        net_all_high = NetworkScanResultsDb.objects.filter(username=username,
                                                           project_id=project_id,
                                                           severity='Medium')

        pentest_all_high = manual_scan_results_db.objects.filter(username=username, severity='Medium',
                                                                 project_id=project_id)

    elif severity == 'Network':
        net_all_high = NetworkScanResultsDb.objects.filter(username=username, false_positive='No')

    elif severity == 'Static':
        sast_all_high = StaticScanResultsDb.objects.filter(username=username, false_positive='No')
        pentest_all_high = manual_scan_results_db.objects.filter(username=username, pentest_type='static')

    elif severity == 'Total':
        # add your scanner name here <scannername>
        web_all_high = WebScanResultsDb.objects.filter(username=username,
                                                       project_id=project_id,)
        sast_all_high = StaticScanResultsDb.objects.filter(username=username,
                                                           project_id=project_id,
                                                           )
        net_all_high = NetworkScanResultsDb.objects.filter(username=username,
                                                              project_id=project_id,
                                                              )

        pentest_all_high = manual_scan_results_db.objects.filter(username=username, project_id=project_id)

    elif severity == 'Web':
        web_all_high = WebScanResultsDb.objects.filter(username=username, false_positive='No')
        pentest_all_high = manual_scan_results_db.objects.filter(username=username, pentest_type='web')

    else:
        return HttpResponseRedirect(
            reverse(f'dashboard:proj_data?project_id={project_id}')
        )

    # add your scanner name here <scannername>
    return render(request,
                  'dashboard/all_high_vuln.html',
                  {'web_all_high': web_all_high,
                   'sast_all_high': sast_all_high,
                   'net_all_high': net_all_high,
                   'pentest_all_high': pentest_all_high,
                   'project_id': project_id,
                   'severity': severity,
                   'message': all_notify,
                   })


def export(request):
    """
    :param request:
    :return:
    """
    if request.method != 'POST':
        return
    project_id = request.POST.get("project_id")
    report_type = request.POST.get("type")
    severity = request.POST.get("severity")

    resource = AllResource()

    username = request.user.username

    all_data = scans_query.all_vuln_count(username=username, project_id=project_id, query=severity)

    dataset = resource.export(all_data)

    if report_type == 'csv':
        response = HttpResponse(dataset.csv, content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="{project_id}.csv"'
        return response
    if report_type == 'json':
        response = HttpResponse(dataset.json, content_type='application/json')
        response['Content-Disposition'] = f'attachment; filename="{project_id}.json"'
        return response
