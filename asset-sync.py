import requests, json, os
from dictor import dictor

""" Rough Outline for Script:
    - Technical info
        - System Info, Logical drives, software/programs (Windows)
        - System Info, Mounts, Applications (macOS)
        - OS detection from JC System Insights will need to be based on the Kernel info
    - User/location association
        - Either based on local device accounts or system association with a user, determine if device is checked out to an employee or not
        - Location will need to be based on either employee info or remote IP of machine; latter will require a geoip module for Python
    - Category association (laptop v. desktop)
        - Can't check Wifi status as it apparently does not exist in Windows...
"""

def jcinfo():
    jcv1url = "https://console.jumpcloud.com/api"
    jcv2url = "https://console.jumpcloud.com/api/v2"
    jcapikey = os.environ['JCAPIKey']
    jcorgid = os.environ['JCOrgID']
    jcsi_path = "/systeminsights"
    jcsinfo_url = jcv2url + jcsi_path + "/system_info"
    jckerninfo_url = jcv2url + jcsi_path + "/kernel_info"
    jcdiskinfo_url = jcv2url + jcsi_path + "/disk_info"
    jcmounts_url = jcv2url + jcsi_path + "/mounts"
    jcloggedusers_url = jcv2url + jcsi_path + "/logged_in_users"
    jcuser_url = jcv1url + "/systemusers"
    jcheaders = {
        'x-org-id': jcorgid, # JumpCloud Org ID should be set as an env variable
        'x-api-key': jcapikey
    }

    sysinfo_res = requests.get(jcsinfo_url, headers=jcheaders)
    jc_json = json.loads(sysinfo_res.text)

    jc_arr = []
    for machine in jc_json:
        m_sysid = machine['system_id']
        m_name = machine['computer_name']
        m_cpu = machine['cpu_brand']
        m_ram = str(round(int(machine['physical_memory']) / 1024 / 1024 / 1024, 0)) + " GB"
        m_serial = machine['hardware_serial']
        m_manufacturer = machine['hardware_vendor']
        m_model = machine['hardware_model']
        m_disk = ""
        m_user = "" 
        user_fn = ""
        user_eid = ""
        user_dept = ""
        user_ccc = ""
        # user_mgr = ""
        info_filter = "?filter=system_id:eq:" + m_sysid
        kinfo_req = jckerninfo_url + info_filter
        sys_kinfo = requests.get(kinfo_req, headers=jcheaders)
        kern_info = json.loads(sys_kinfo.text)
        win_kern_path = 'C:\\WINDOWS\\System32\\ntoskrnl.exe'
        kern_string = str(kern_info[0]['path'])
        if kern_string.lower() == win_kern_path.lower():
            dinfo_url = jcdiskinfo_url + info_filter
            sys_dinfo = requests.get(dinfo_url, headers=jcheaders)
            disk_info = json.loads(sys_dinfo.text)
            m_disk = str(round(int(disk_info[0]['disk_size']) / 1000 / 1000 / 1000, 0)) + " GB"
            loguser_req = jcloggedusers_url + info_filter
            sys_userinfo = requests.get(loguser_req, headers=jcheaders)
            sys_users = json.loads(sys_userinfo.text)
            for sys_user in sys_users:
                if (sys_user['type'] == 'active') & (sys_user['username'] != '') & (sys_user['username'] != 'Administrator'):
                    m_user = sys_user['username']
                    user_fields = "?fields=firstname lastname employeeIdentifier department costCenter attributes"
                    user_filter = "&filter=username:eq:" + m_user
                    jcuser_req = jcuser_url + user_fields + user_filter
                    user_resp = requests.get(jcuser_req, headers=jcheaders)
                    user_info = json.loads(user_resp.text)
        elif kern_string.lower() != win_kern_path.lower():
            dinfo_url = jcmounts_url + info_filter
            sys_dinfo = requests.get(dinfo_url, headers=jcheaders)
            disk_info = json.loads(sys_dinfo.text)
            for disk in disk_info:
                if disk['path'] == "/":
                    m_disk = str(round(int(disk['blocks']) * int(disk['blocks_size']) / 1000000000, 0)) + " GB"
                else:
                    continue
            loguser_req = jcloggedusers_url + info_filter
            sys_userinfo = requests.get(loguser_req, headers=jcheaders)
            sys_users = json.loads(sys_userinfo.text)
            m_user = sys_users[0]['username']
            user_fields = "?fields=firstname lastname employeeIdentifier department costCenter attributes"
            user_filter = "&filter=username:eq:" + m_user
            jcuser_req = jcuser_url + user_fields + user_filter
            user_resp = requests.get(jcuser_req, headers=jcheaders)
            user_info = json.loads(user_resp.text)
        if len(user_info['results']):
            user_fn = user_info['results'][0]['firstname'] + " " + user_info['results'][0]['lastname']
            user_eid = user_info['results'][0]['employeeIdentifier']
            user_dept = user_info['results'][0]['department']
            user_ccc = user_info['results'][0]['costCenter']
            # user_mgr = user_info['results'][0]['attributes'][0]['value']
        else:
            continue
        jcdata = {
            'm_sysid': m_sysid,
            'm_name': m_name,
            'm_cpu': m_cpu,
            'm_ram': m_ram,
            'm_serial': m_serial,
            'm_manufacturer': m_manufacturer,
            'm_model': m_model,
            'm_disk': m_disk,
            'm_user': m_user,
            'user_fn': user_fn,
            'user_eid': user_eid,
            'user_dept': user_dept,
            'user_ccc': user_ccc
        }
        jc_arr.append(jcdata)
    return jc_arr

def snipeit_pop(jc_machines):
    sit_api = "https://pacteraedge.snipe-it.io/api/v1"
    sit_token = os.environ['SITToken']
    sit_headers = { 'Authorization': 'Bearer ' + sit_token }

    for jcm in jc_machines:
        dept_param = { "search": jcm['user_dept']}
        dept_list_req = requests.get(str(sit_api + "/departments"), headers=sit_headers, params=dept_param)
        sit_depts = json.loads(dept_list_req.text)
        dept_list = dictor(sit_depts, 'rows')
        sit_depname = dept_list[0]['name']

        if str(jcm['user_dept']).replace('&', '&amp;') != sit_depname:
            payload = {'name': jcm['user_dept']}
            dept_resp = requests.post(str(sit_api + "/departments"), data=payload, headers=sit_headers)
            print(dept_resp.text)

        manu_param = { "search": jcm['m_manufacturer']}
        manu_list_req = requests.get(str(sit_api + "/manufacturers"), headers=sit_headers, params=manu_param)
        sit_manus = json.loads(manu_list_req.text)    
        manu_list = dictor(sit_manus, 'rows')
        sit_manu = manu_list[0]['name']

        if jcm['m_manufacturer'] != sit_manu:
            payload = {'name': jcm['m_manufacturer']}
            manu_resp = requests.post(str(sit_api + "/manufacturers"), data=payload, headers=sit_headers)

        model_param = { "search": jcm['m_model']}
        model_list_req = requests.get(str(sit_api + "/models"), headers=sit_headers, params=model_param)
        sit_models = json.loads(model_list_req.text)
        if sit_models['total'] == 0:
            manu_id = manu_list[0]['id']
            payload = {'name': jcm['m_model'], 'category_id': 5, 'manufacturer_id': manu_id, 'fieldset_id': 2 }
            model_resp = requests.post(str(sit_api + "/models"), data=payload, headers=sit_headers)
            model_info = json.loads(model_resp.text)
            sit_model = dictor(model_info, 'payload')
            model_id = sit_model['id']
        else:
            sit_model = dictor(sit_models, 'rows')
            model_id = sit_model[0]['id']

        hw_check_req = requests.get(str(sit_api + "/hardware/byserial/" + jcm['m_serial']), headers=sit_headers)
        sit_asset = json.loads(hw_check_req.text)
        if sit_asset['total'] == 0:
            payload = { 
                'name': jcm['m_name'],
                'model_id': model_id, 
                'status_id': 2, 
                'serial': jcm['m_serial'],
                '_snipeit_employee_id_7': jcm['user_eid'], 
                '_snipeit_employee_name_8': jcm['user_fn'], 
                '_snipeit_cost_center_name_14': jcm['user_dept'],
                '_snipeit_asset_description_10': str(f"CPU: {jcm['m_cpu']}, RAM: {jcm['m_ram']}, Storage: {jcm['m_disk']}")
            }
            create_asset = requests.post(str(sit_api + "/hardware"), data=payload, headers=sit_headers)
        else:
            asset_info = dictor(sit_asset, 'rows')
            asset_id = str(asset_info[0]['id'])
            payload = { 
                'name': jcm['m_name'],
                'model_id': model_id, 
                'status_id': 2, 
                'serial': jcm['m_serial'],
                '_snipeit_employee_id_7': jcm['user_eid'], 
                '_snipeit_employee_name_8': jcm['user_fn'], 
                '_snipeit_cost_center_name_14': jcm['user_dept'],
                '_snipeit_asset_description_10': str(f"CPU: {jcm['m_cpu']}, RAM: {jcm['m_ram']}, Storage: {jcm['m_disk']}")
            }
            update_asset = requests.patch(str(sit_api + "/hardware/" + asset_id), data=payload, headers=sit_headers)

if __name__ == "__main__":
    snipeit_pop(jcinfo())