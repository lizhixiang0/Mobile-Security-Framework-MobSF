<<<<<<< HEAD
# -*- coding: utf_8 -*-
"""MobSF REST API V 1."""

from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt

from MobSF.utils import api_key
from MobSF.views.helpers import request_method
from MobSF.views.home import RecentScans, Upload, delete_scan

from StaticAnalyzer.views.android import view_source
from StaticAnalyzer.views.android.static_analyzer import static_analyzer, get_app_name, copy_icon, valid_android_zip
from StaticAnalyzer.views.ios import view_source as ios_view_source
from StaticAnalyzer.views.ios.static_analyzer import static_analyzer_ios
from StaticAnalyzer.views.shared_func import pdf
from StaticAnalyzer.views.windows import windows
import logging
import os
import re
import shutil

import MalwareAnalyzer.views.Trackers as Trackers
import MalwareAnalyzer.views.VirusTotal as VirusTotal
from MalwareAnalyzer.views.apkid import apkid_analysis
from MalwareAnalyzer.views.domain_check import malware_check

from django.conf import settings
from django.http import HttpResponseRedirect
from django.shortcuts import render
from MobSF.utils import (
    file_size,
    is_file_exists,
    print_n_send_error_response,
)

from StaticAnalyzer.models import StaticAnalyzerAndroid
from StaticAnalyzer.views.android.binary_analysis import (elf_analysis,
                                                          res_analysis)
from StaticAnalyzer.views.android.cert_analysis import (
    cert_info, get_hardcoded_cert_keystore)
from StaticAnalyzer.views.android.code_analysis import code_analysis
from StaticAnalyzer.views.android.converter import (apk_2_java, dex_2_smali)
from StaticAnalyzer.views.android.db_interaction import (
    get_context_from_analysis, get_context_from_db_entry, save_or_update)
from StaticAnalyzer.views.android.icon_analysis import (find_icon_path_zip,
                                                        get_icon)
from StaticAnalyzer.views.android.manifest_analysis import (get_manifest,
                                                            manifest_analysis,
                                                            manifest_data)
from StaticAnalyzer.views.android.playstore import get_app_details
from StaticAnalyzer.views.android.strings import strings_jar
from StaticAnalyzer.views.shared_func import (firebase_analysis,
                                              hash_gen, score, unzip,
                                              update_scan_timestamp)

from androguard.core.bytecodes import apk


logger = logging.getLogger(__name__)
OK = 200


def make_api_response(data, status=OK):
    """Make API Response."""
    resp = JsonResponse(data=data, status=status)
    resp['Access-Control-Allow-Origin'] = '*'
    resp['Access-Control-Allow-Methods'] = 'POST'
    resp['Access-Control-Allow-Headers'] = 'Authorization'
    resp['Content-Type'] = 'application/json; charset=utf-8'
    return resp


def api_auth(meta):
    """Check if API Key Matches."""
    if 'HTTP_AUTHORIZATION' in meta:
        return bool(api_key() == meta['HTTP_AUTHORIZATION'])
    return False


@request_method(['POST'])
@csrf_exempt
def api_upload(request):
    """POST - Upload API."""
    upload = Upload(request)
    resp, code = upload.upload_api()
    """Do static analysis on an request and save to db."""
    try:
        typ = resp['scan_type']
        checksum = resp['hash']
        filename = resp['file_name']
        rescan = str(0)

        app_dic = {}
        match = re.match('^[0-9a-f]{32}$', checksum)
        if (
                (
                        match
                ) and (
                filename.lower().endswith('.apk')
                or filename.lower().endswith('.zip')
        ) and (
                typ in ['zip', 'apk']
        )
        ):
            app_dic['dir'] = settings.BASE_DIR  # BASE DIR
            app_dic['app_name'] = filename  # APP ORGINAL NAME
            app_dic['md5'] = checksum  # MD5
            # APP DIRECTORY
            app_dic['app_dir'] = os.path.join(settings.UPLD_DIR, app_dic[
                'md5'] + '/')
            app_dic['tools_dir'] = os.path.join(
                app_dic['dir'], 'StaticAnalyzer/tools/')  # TOOLS DIR
            logger.info('Starting Analysis on : %s', app_dic['app_name'])

            if typ == 'apk':
                # Check if in DB
                # pylint: disable=E1101
                db_entry = StaticAnalyzerAndroid.objects.filter(
                    MD5=app_dic['md5'])
                if db_entry.exists() and rescan == '0':
                    # 如果数据库能够直接查出结果，且不重新扫描，就执行下一句
                    context = get_context_from_db_entry(db_entry)
                else:
                    app_dic['app_file'] = app_dic[
                                              'md5'] + '.apk'  # NEW FILENAME
                    app_dic['app_path'] = (app_dic['app_dir']
                                           + app_dic['app_file'])  # APP PATH

                    # ANALYSIS BEGINS
                    app_dic['size'] = str(
                        file_size(app_dic['app_path'])) + 'MB'  # FILE SIZE
                    app_dic['sha1'], app_dic[
                        'sha256'] = hash_gen(app_dic['app_path'])

                    app_dic['files'] = unzip(
                        app_dic['app_path'], app_dic['app_dir'])
                    if not app_dic['files']:
                        # Can't Analyze APK, bail out.
                        msg = 'APK file is invalid or corrupt'

                        return print_n_send_error_response(
                            request,
                            msg,
                            True)
                    app_dic['certz'] = get_hardcoded_cert_keystore(app_dic[
                                                                       'files'])

                    logger.info('APK Extracted')

                    # Manifest XML
                    app_dic['parsed_xml'] = get_manifest(
                        app_dic['app_path'],
                        app_dic['app_dir'],
                        app_dic['tools_dir'],
                        '',
                        True,
                    )

                    # get app_name
                    app_dic['real_name'] = get_app_name(
                        app_dic['app_path'],
                        app_dic['app_dir'],
                        app_dic['tools_dir'],
                        True,
                    )

                    # Get icon
                    res_path = os.path.join(app_dic['app_dir'], 'res')
                    app_dic['icon_hidden'] = True
                    # Even if the icon is hidden, try to guess it by the
                    # default paths
                    app_dic['icon_found'] = False
                    app_dic['icon_path'] = ''
                    # TODO: Check for possible different names for resource
                    # folder?
                    if os.path.exists(res_path):
                        icon_dic = get_icon(
                            app_dic['app_path'], res_path)
                        if icon_dic:
                            app_dic['icon_hidden'] = icon_dic['hidden']
                            app_dic['icon_found'] = bool(icon_dic['path'])
                            app_dic['icon_path'] = icon_dic['path']

                    # Set Manifest link
                    app_dic['mani'] = ('../ManifestView/?md5='
                                       + app_dic['md5']
                                       + '&type=apk&bin=1')
                    man_data_dic = manifest_data(app_dic['parsed_xml'])
                    app_dic['playstore'] = get_app_details(
                        man_data_dic['packagename'])
                    man_an_dic = manifest_analysis(
                        app_dic['parsed_xml'],
                        man_data_dic)
                    bin_an_buff = []
                    bin_an_buff += elf_analysis(app_dic['app_dir'])
                    bin_an_buff += res_analysis(app_dic['app_dir'])
                    cert_dic = cert_info(
                        app_dic['app_dir'],
                        app_dic['app_file'])

                    # apkid扫描
                    apkid_results = apkid_analysis(app_dic[
                                                       'app_dir'], app_dic['app_path'], app_dic['app_name'])
                    tracker = Trackers.Trackers(
                        app_dic['app_dir'], app_dic['tools_dir'])
                    tracker_res = tracker.get_trackers()

                    apk_2_java(app_dic['app_path'], app_dic['app_dir'],
                               app_dic['tools_dir'])

                    dex_2_smali(app_dic['app_dir'], app_dic['tools_dir'])

                    code_an_dic = code_analysis(
                        app_dic['app_dir'],
                        man_an_dic['permissons'],
                        'apk')

                    # Get the strings
                    string_res = strings_jar(
                        app_dic['app_file'],
                        app_dic['app_dir'])
                    if string_res:
                        app_dic['strings'] = string_res['strings']
                        code_an_dic['urls_list'].extend(
                            string_res['urls_list'])
                        code_an_dic['urls'].extend(string_res['url_nf'])
                        code_an_dic['emails'].extend(string_res['emails_nf'])
                    else:
                        app_dic['strings'] = []

                    # Firebase DB Check
                    code_an_dic['firebase'] = firebase_analysis(
                        list(set(code_an_dic['urls_list'])))
                    # Domain Extraction and Malware Check
                    logger.info(
                        'Performing Malware Check on extracted Domains')
                    code_an_dic['domains'] = malware_check(
                        list(set(code_an_dic['urls_list'])))
                    # Copy App icon
                    copy_icon(app_dic['md5'], app_dic['icon_path'])
                    app_dic['zipped'] = 'apk'

                    logger.info('Connecting to Database')
                    try:
                        # SAVE TO DB
                        if rescan == '1':
                            logger.info('Updating Database...')
                            save_or_update(
                                'update',
                                app_dic,
                                man_data_dic,
                                man_an_dic,
                                code_an_dic,
                                cert_dic,
                                bin_an_buff,
                                apkid_results,
                                tracker_res,
                            )
                            update_scan_timestamp(app_dic['md5'])
                        elif rescan == '0':
                            logger.info('Saving to Database')
                            save_or_update(
                                'save',
                                app_dic,
                                man_data_dic,
                                man_an_dic,
                                code_an_dic,
                                cert_dic,
                                bin_an_buff,
                                apkid_results,
                                tracker_res,
                            )
                    except Exception:
                        logger.exception('Saving to Database Failed')
                    context = get_context_from_analysis(
                        app_dic,
                        man_data_dic,
                        man_an_dic,
                        code_an_dic,
                        cert_dic,
                        bin_an_buff,
                        apkid_results,
                        tracker_res,
                    )
                context['average_cvss'], context[
                    'security_score'] = score(context['code_analysis'])
                context['dynamic_analysis_done'] = is_file_exists(
                    os.path.join(app_dic['app_dir'], 'logcat.txt'))

                context['virus_total'] = None
                if settings.VT_ENABLED:
                    vt = VirusTotal.VirusTotal()
                    context['virus_total'] = vt.get_result(
                        os.path.join(app_dic['app_dir'],
                                     app_dic['md5']) + '.apk',
                        app_dic['md5'])
                template = 'static_analysis/android_binary_analysis.html'
                return make_api_response(context, code)
            elif typ == 'zip':
                # Check if in DB
                # pylint: disable=E1101
                cert_dic = {
                    'certificate_info': '',
                    'certificate_status': '',
                    'description': '',
                }
                bin_an_buff = []
                app_dic['strings'] = ''
                app_dic['zipped'] = ''
                # Above fields are only available for APK and not ZIP
                db_entry = StaticAnalyzerAndroid.objects.filter(
                    MD5=app_dic['md5'])
                if db_entry.exists() and rescan == '0':
                    context = get_context_from_db_entry(db_entry)
                else:
                    app_dic['app_file'] = app_dic[
                                              'md5'] + '.zip'  # NEW FILENAME
                    app_dic['app_path'] = (app_dic['app_dir']
                                           + app_dic['app_file'])  # APP PATH
                    logger.info('Extracting ZIP')
                    app_dic['files'] = unzip(
                        app_dic['app_path'], app_dic['app_dir'])
                    # Check if Valid Directory Structure and get ZIP Type
                    pro_type, valid = valid_android_zip(app_dic['app_dir'])
                    if valid and pro_type == 'ios':
                        logger.info('Redirecting to iOS Source Code Analyzer')

                        return {'type': 'ios'}

                    app_dic['certz'] = get_hardcoded_cert_keystore(
                        app_dic['files'])
                    app_dic['zipped'] = pro_type
                    logger.info('ZIP Type - %s', pro_type)
                    if valid and (pro_type in ['eclipse', 'studio']):
                        # ANALYSIS BEGINS
                        app_dic['size'] = str(
                            file_size(app_dic['app_path'])) + 'MB'  # FILE SIZE
                        app_dic['sha1'], app_dic[
                            'sha256'] = hash_gen(app_dic['app_path'])

                        # Manifest XML
                        app_dic['persed_xml'] = get_manifest(
                            '',
                            app_dic['app_dir'],
                            app_dic['tools_dir'],
                            pro_type,
                            False,
                        )

                        # get app_name
                        app_dic['real_name'] = get_app_name(
                            app_dic['app_path'],
                            app_dic['app_dir'],
                            app_dic['tools_dir'],
                            False,
                        )

                        # Set manifest view link
                        app_dic['mani'] = (
                                '../ManifestView/?md5='
                                + app_dic['md5'] + '&type='
                                + pro_type + '&bin=0'
                        )

                        man_data_dic = manifest_data(app_dic['persed_xml'])
                        app_dic['playstore'] = get_app_details(
                            man_data_dic['packagename'])
                        man_an_dic = manifest_analysis(
                            app_dic['persed_xml'],
                            man_data_dic,
                        )
                        # Get icon
                        eclipse_res_path = os.path.join(
                            app_dic['app_dir'], 'res')
                        studio_res_path = os.path.join(
                            app_dic['app_dir'], 'app', 'src', 'main', 'res')
                        if os.path.exists(eclipse_res_path):
                            res_path = eclipse_res_path
                        elif os.path.exists(studio_res_path):
                            res_path = studio_res_path
                        else:
                            res_path = ''

                        app_dic['icon_hidden'] = man_an_dic['icon_hidden']
                        app_dic['icon_found'] = False
                        app_dic['icon_path'] = ''
                        if res_path:
                            app_dic['icon_path'] = find_icon_path_zip(
                                res_path, man_data_dic['icons'])
                            if app_dic['icon_path']:
                                app_dic['icon_found'] = True

                        if app_dic['icon_path']:
                            if os.path.exists(app_dic['icon_path']):
                                shutil.copy2(
                                    app_dic['icon_path'],
                                    os.path.join(
                                        settings.DWD_DIR,
                                        app_dic['md5'] + '-icon.png'))

                        code_an_dic = code_analysis(
                            app_dic['app_dir'],
                            man_an_dic['permissons'],
                            pro_type)
                        # Firebase DB Check
                        code_an_dic['firebase'] = firebase_analysis(
                            list(set(code_an_dic['urls_list'])))
                        # Domain Extraction and Malware Check
                        logger.info(
                            'Performing Malware Check on extracted Domains')
                        code_an_dic['domains'] = malware_check(
                            list(set(code_an_dic['urls_list'])))
                        logger.info('Connecting to Database')
                        try:
                            # SAVE TO DB
                            if rescan == '1':
                                logger.info('Updating Database...')
                                save_or_update(
                                    'update',
                                    app_dic,
                                    man_data_dic,
                                    man_an_dic,
                                    code_an_dic,
                                    cert_dic,
                                    bin_an_buff,
                                    {},
                                    {},
                                )
                                update_scan_timestamp(app_dic['md5'])
                            elif rescan == '0':
                                logger.info('Saving to Database')
                                save_or_update(
                                    'save',
                                    app_dic,
                                    man_data_dic,
                                    man_an_dic,
                                    code_an_dic,
                                    cert_dic,
                                    bin_an_buff,
                                    {},
                                    {},
                                )
                        except Exception:
                            logger.exception('Saving to Database Failed')
                        context = get_context_from_analysis(
                            app_dic,
                            man_data_dic,
                            man_an_dic,
                            code_an_dic,
                            cert_dic,
                            bin_an_buff,
                            {},
                            {},
                        )
                    else:
                        msg = 'This ZIP Format is not supported'

                        return print_n_send_error_response(
                            request,
                            msg,
                            True)

                context['average_cvss'], context[
                    'security_score'] = score(context['code_analysis'])
                template = 'static_analysis/android_source_analysis.html'

                return context

            else:
                err = ('Only APK,IPA and Zipped '
                       'Android/iOS Source code supported now!')
                logger.error(err)
        else:
            msg = 'Hash match failed or Invalid file extension or file type'
            return print_n_send_error_response(request, msg, True)

    except Exception as excep:
        logger.exception('Error Performing Static Analysis')
        msg = str(excep)
        exp = excep.__doc__
        return print_n_send_error_response(request, msg, True, exp)

@request_method(['GET'])
@csrf_exempt
def api_recent_scans(request):
    """GET - get recent scans."""
    scans = RecentScans(request)
    resp = scans.recent_scans()
    if 'error' in resp:
        return make_api_response(resp, 500)
    else:
        return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_scan(request):
    """POST - Scan API."""
    params = {'scan_type', 'hash', 'file_name'}
    if set(request.POST) >= params:
        scan_type = request.POST['scan_type']
        # APK, Android ZIP and iOS ZIP
        if scan_type in {'apk', 'zip'}:
            resp = static_analyzer(request, True)
            if 'type' in resp:
                # For now it's only ios_zip
                request.POST._mutable = True
                request.POST['scan_type'] = 'ios'
                resp = static_analyzer_ios(request, True)
            if 'error' in resp:
                response = make_api_response(resp, 500)
            else:
                response = make_api_response(resp, 200)
        # IPA
        elif scan_type == 'ipa':
            resp = static_analyzer_ios(request, True)
            if 'error' in resp:
                response = make_api_response(resp, 500)
            else:
                response = make_api_response(resp, 200)
        # APPX
        elif scan_type == 'appx':
            resp = windows.staticanalyzer_windows(request, True)
            if 'error' in resp:
                response = make_api_response(resp, 500)
            else:
                response = make_api_response(resp, 200)
    else:
        response = make_api_response(
            {'error': 'Missing Parameters'}, 422)
    return response


@request_method(['POST'])
@csrf_exempt
def api_delete_scan(request):
    """POST - Delete a Scan."""
    if 'hash' in request.POST:
        resp = delete_scan(request, True)
        if 'error' in resp:
            response = make_api_response(resp, 500)
        else:
            response = make_api_response(resp, 200)
    else:
        response = make_api_response(
            {'error': 'Missing Parameters'}, 422)
    return response


@request_method(['POST'])
@csrf_exempt
def api_pdf_report(request):
    """Generate and Download PDF."""
    params = {'hash'}
    if set(request.POST) == params:
        resp = pdf(request, api=True)
        if 'error' in resp:
            if resp.get('error') == 'Invalid scan hash':
                response = make_api_response(resp, 400)
            else:
                response = make_api_response(resp, 500)
        elif 'pdf_dat' in resp:
            response = HttpResponse(
                resp['pdf_dat'], content_type='application/pdf')
            response['Access-Control-Allow-Origin'] = '*'
        elif resp.get('report') == 'Report not Found':
            response = make_api_response(resp, 404)
        else:
            response = make_api_response(
                {'error': 'PDF Generation Error'}, 500)
    else:
        response = make_api_response(
            {'error': 'Missing Parameters'}, 422)
    return response


@request_method(['POST'])
@csrf_exempt
def api_json_report(request):
    """Generate JSON Report."""
    params = {'hash'}
    if set(request.POST) == params:
        resp = pdf(request, api=True, jsonres=True)
        if 'error' in resp:
            if resp.get('error') == 'Invalid scan hash':
                response = make_api_response(resp, 400)
            else:
                response = make_api_response(resp, 500)
        elif 'report_dat' in resp:
            response = make_api_response(resp['report_dat'], 200)
        elif resp.get('report') == 'Report not Found':
            response = make_api_response(resp, 404)
        else:
            response = make_api_response(
                {'error': 'JSON Generation Error'}, 500)
    else:
        response = make_api_response(
            {'error': 'Missing Parameters'}, 422)
    return response


@request_method(['POST'])
@csrf_exempt
def api_view_source(request):
    """View Source for android & ios source file."""
    params = {'file', 'type', 'hash'}
    if set(request.POST) >= params:
        if request.POST['type'] in {'eclipse', 'studio', 'apk'}:
            resp = view_source.run(request, api=True)
        else:
            resp = ios_view_source.run(request, api=True)
        if 'error' in resp:
            response = make_api_response(resp, 500)
        else:
            response = make_api_response(resp, 200)
    else:
        response = make_api_response({'error': 'Missing Parameters'}, 422)
    return response
=======
# -*- coding: utf_8 -*-
"""MobSF REST API V 1."""

from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt

from MobSF.utils import api_key
from MobSF.views.helpers import request_method
from MobSF.views.home import RecentScans, Upload, delete_scan

from StaticAnalyzer.views.android import view_source
from StaticAnalyzer.views.android.static_analyzer import static_analyzer
from StaticAnalyzer.views.ios import view_source as ios_view_source
from StaticAnalyzer.views.ios.static_analyzer import static_analyzer_ios
from StaticAnalyzer.views.shared_func import pdf
from StaticAnalyzer.views.windows import windows

OK = 200


def make_api_response(data, status=OK):
    """Make API Response."""
    resp = JsonResponse(data=data, status=status)
    resp['Access-Control-Allow-Origin'] = '*'
    resp['Access-Control-Allow-Methods'] = 'POST'
    resp['Access-Control-Allow-Headers'] = 'Authorization'
    resp['Content-Type'] = 'application/json; charset=utf-8'
    return resp


def api_auth(meta):
    """Check if API Key Matches."""
    if 'HTTP_AUTHORIZATION' in meta:
        return bool(api_key() == meta['HTTP_AUTHORIZATION'])
    return False


@request_method(['POST'])
@csrf_exempt
def api_upload(request):
    """POST - Upload API."""
    upload = Upload(request)
    resp, code = upload.upload_api()
    return make_api_response(resp, code)


@request_method(['GET'])
@csrf_exempt
def api_recent_scans(request):
    """GET - get recent scans."""
    scans = RecentScans(request)
    resp = scans.recent_scans()
    if 'error' in resp:
        return make_api_response(resp, 500)
    else:
        return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_scan(request):
    """POST - Scan API."""
    params = {'scan_type', 'hash', 'file_name'}
    if set(request.POST) >= params:
        scan_type = request.POST['scan_type']
        # APK, Android ZIP and iOS ZIP
        if scan_type in {'apk', 'zip'}:
            resp = static_analyzer(request, True)
            if 'type' in resp:
                # For now it's only ios_zip
                request.POST._mutable = True
                request.POST['scan_type'] = 'ios'
                resp = static_analyzer_ios(request, True)
            if 'error' in resp:
                response = make_api_response(resp, 500)
            else:
                response = make_api_response(resp, 200)
        # IPA
        elif scan_type == 'ipa':
            resp = static_analyzer_ios(request, True)
            if 'error' in resp:
                response = make_api_response(resp, 500)
            else:
                response = make_api_response(resp, 200)
        # APPX
        elif scan_type == 'appx':
            resp = windows.staticanalyzer_windows(request, True)
            if 'error' in resp:
                response = make_api_response(resp, 500)
            else:
                response = make_api_response(resp, 200)
    else:
        response = make_api_response(
            {'error': 'Missing Parameters'}, 422)
    return response


@request_method(['POST'])
@csrf_exempt
def api_delete_scan(request):
    """POST - Delete a Scan."""
    if 'hash' in request.POST:
        resp = delete_scan(request, True)
        if 'error' in resp:
            response = make_api_response(resp, 500)
        else:
            response = make_api_response(resp, 200)
    else:
        response = make_api_response(
            {'error': 'Missing Parameters'}, 422)
    return response


@request_method(['POST'])
@csrf_exempt
def api_pdf_report(request):
    """Generate and Download PDF."""
    params = {'hash'}
    if set(request.POST) == params:
        resp = pdf(request, api=True)
        if 'error' in resp:
            if resp.get('error') == 'Invalid scan hash':
                response = make_api_response(resp, 400)
            else:
                response = make_api_response(resp, 500)
        elif 'pdf_dat' in resp:
            response = HttpResponse(
                resp['pdf_dat'], content_type='application/pdf')
            response['Access-Control-Allow-Origin'] = '*'
        elif resp.get('report') == 'Report not Found':
            response = make_api_response(resp, 404)
        else:
            response = make_api_response(
                {'error': 'PDF Generation Error'}, 500)
    else:
        response = make_api_response(
            {'error': 'Missing Parameters'}, 422)
    return response


@request_method(['POST'])
@csrf_exempt
def api_json_report(request):
    """Generate JSON Report."""
    params = {'hash'}
    if set(request.POST) == params:
        resp = pdf(request, api=True, jsonres=True)
        if 'error' in resp:
            if resp.get('error') == 'Invalid scan hash':
                response = make_api_response(resp, 400)
            else:
                response = make_api_response(resp, 500)
        elif 'report_dat' in resp:
            response = make_api_response(resp['report_dat'], 200)
        elif resp.get('report') == 'Report not Found':
            response = make_api_response(resp, 404)
        else:
            response = make_api_response(
                {'error': 'JSON Generation Error'}, 500)
    else:
        response = make_api_response(
            {'error': 'Missing Parameters'}, 422)
    return response


@request_method(['POST'])
@csrf_exempt
def api_view_source(request):
    """View Source for android & ios source file."""
    params = {'file', 'type', 'hash'}
    if set(request.POST) >= params:
        if request.POST['type'] in {'eclipse', 'studio', 'apk'}:
            resp = view_source.run(request, api=True)
        else:
            resp = ios_view_source.run(request, api=True)
        if 'error' in resp:
            response = make_api_response(resp, 500)
        else:
            response = make_api_response(resp, 200)
    else:
        response = make_api_response({'error': 'Missing Parameters'}, 422)
    return response
>>>>>>> 0e25bd1b7f0ac52d875766e80a7158f5e5832e2f
