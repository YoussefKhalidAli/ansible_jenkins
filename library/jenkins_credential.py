#!/usr/bin/python

from ansible.module_utils.basic import AnsibleModule
import json
import subprocess
import os
import base64
import urllib.request

# Gets the Jenkins crumb for CSRF protection which is required for API calls
def get_jenkins_crumb(url, user, token):
    """Fetch Jenkins crumb from the crumb issuer API."""
    crumb_url = f"{url}/crumbIssuer/api/json"

    # Basic Auth header encoding
    auth = f"{user}:{token}".encode('utf-8')
    b64_auth = base64.b64encode(auth).decode('utf-8')
    headers = {
        "Authorization": f"Basic {b64_auth}",
        "Accept": "application/json"
    }

    req = urllib.request.Request(crumb_url, headers=headers)

    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            # The JSON usually has "crumbRequestField" and "crumb"
            return data["crumbRequestField"], data["crumb"]
    except Exception as e:
        return None, None
    
# Main function to run the Ansible module

def run_module():
    module_args = dict(
        name=dict(type='str', required=True), # Id
        type=dict(type='str', required=False, choices=['userAndPass', 'file', 'text', "githubApp", "sshKey", "certificate", "scope"]), # Credential type
        command=dict(type='str', required=False, default='add', choices=['add', 'delete', 'update']), # Command to execute
        scope=dict(type='str', required=False, default='_'), # Scope of the credential
        url=dict(type='str', required=False, default='http://localhost:8080'), # Jenkins URL
        jenkinsUser=dict(type='str', required=True), # Jenkins username
        token=dict(type='str', required=True, no_log=True), # Jenkins API token
        description=dict(type='str', required=False, default=''), # Description of the credential
        username=dict(type='str', required=False),# Username for userAndPass and sshKey types
        password=dict(type='str', required=False, no_log=True), # Password for userAndPass type
        filePath=dict(type='str', required=False, default = None), # File path for file and sshKey types
        text=dict(type='str', required=False, no_log=True), # Text for text type
        appId=dict(type='str', required=False), # App ID for githubApp type
        owner=dict(type='str', required=False, default=''), # Owner for githubApp type
        passPhrase=dict(type='str', required=False, no_log=True), # Passphrase for sshKey type
        privateKeyPath=dict(type='str', required=False), # Private key path for certificate type
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=False
    )

    # Get the crumb for CSRF protection
    crumb_field, crumb_value = get_jenkins_crumb(module.params['url'], module.params['jenkinsUser'], module.params['token'])
    if not crumb_field or not crumb_value:
        module.fail_json(msg="Failed to fetch Jenkins crumb. Check Jenkins URL and credentials.")

    result = dict(
        changed=False,
        message='',
    )

    # Get main parameters
    cred_type = module.params['type']
    command = module.params['command']

    credentials = {
        "id": module.params["name"],
        "description": module.params["description"],
    }

    # Base curl command common params
    base_curl_cmd = [
        'curl',
        '-u', f"{module.params['jenkinsUser']}:{module.params['token']}",
        '-H', f"{crumb_field}:{crumb_value}",
        '-X', 'POST',
    ]

    # Helper to build the payload and curl command for add or update
    def build_curl_for_add_or_update(url_suffix, payload_json, file_path=None):
        
        cmd = base_curl_cmd.copy()
        
        # If file_path is provided, we need to use -F for file upload
        if file_path:
            cmd.append('-F')
            cmd.append(f"file0=@{file_path}")
            cmd.append('-F')

        # If file_path is provided, we need to use -F for file upload
        else:
            cmd.append('-H')
            cmd.append('Content-Type: application/x-www-form-urlencoded')
            cmd.append('--data-urlencode')
        
        cmd.append(f"json={json.dumps(payload_json)}")
        cmd.append(f"{module.params['url']}{url_suffix}")
        
        return cmd

    if command in ['add', 'update']:
        # Check if credential type is provided
        if cred_type == None:
            module.fail_json(msg="Credential type is required for add or update")
            
        url_suffix_base = f"/credentials/store/system/domain/{module.params['scope']}/createCredentials"

        # If updating, we need to delete the existing credential first
        if command == 'update':
            delete_cmd = [
            'curl',
            '-X', 'DELETE',
            '-u', f"{module.params['jenkinsUser']}:{module.params['token']}",
            '-H', f"{crumb_field}:{crumb_value}",
            f"{module.params['url']}/credentials/store/system/domain/_/credential/{module.params['name']}/config.xml"
            ]

            try:
                subprocess.run(delete_cmd, check=True, capture_output=True, text=True)
            except subprocess.CalledProcessError as e:
                module.fail_json(
                    msg="Failed to delete credential before update",
                    stderr=e.stderr,
                    stdout=e.stdout,
                    returncode=e.returncode,
                    curl_command=' '.join(delete_cmd)
                )
            
        if cred_type == 'scope':
            # Create a domain in Jenkins
            payload = {
                "name": module.params["name"],
                "description": module.params["description"],
                "specifications": []  # Optional: could define things like host restrictions
            }

            url_suffix_base = "/credentials/store/system/createDomain"

        # For each credential type build the credentials dict & payload then build curl_cmd
        elif cred_type == 'userAndPass':

            # userAndPass requires username and password
            if not module.params['username'] or not module.params['password']:
                module.fail_json(msg="username and password are required for type 'userAndPass'")

            credentials.update({
                "$class": "com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl",
                "username": module.params["username"],
                "password": module.params["password"]
            })

            payload = {
                "": "0",
                "credentials": credentials
            }

        elif cred_type == 'file':

            # file requires filePath
            if not module.params['filePath']:
                module.fail_json(msg="filePath is required for type 'file'")
            if not os.path.exists(module.params['filePath']):
                module.fail_json(msg=f"File not found: {module.params['filePath']}")

            credentials.update({
                "$class": "org.jenkinsci.plugins.plaincredentials.impl.FileCredentialsImpl",
                "file": "file0",
                "fileName": os.path.basename(module.params['filePath']),
            })

            payload = {
                "": "0",
                "credentials": credentials
            }

        elif cred_type == 'text':
            if not module.params['text']:
                module.fail_json(msg="text is required for type 'text'")

            credentials.update({
                "$class": "org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl",
                "secret": module.params['text'],
            })

            payload = {
                "": "0",
                "credentials": credentials
            }

        elif cred_type == 'githubApp':

            # GitHub App credentials require appId and private key
            if not module.params['appId']:
                module.fail_json(msg="appId is required for type 'githubApp'")
            if not module.params['filePath']:
                module.fail_json(msg="filePath is required for type 'githubApp'")
            if not os.path.exists(module.params['filePath']):
                module.fail_json(msg=f"File not found: {module.params['filePath']}")

            try:
                with open(module.params['filePath'], 'r') as f:
                    private_key = f.read().strip()
            except Exception as e:
                module.fail_json(msg=f"Failed to read private key file: {str(e)}")

            credentials.update({
                "$class": "org.jenkinsci.plugins.github_branch_source.GitHubAppCredentials",
                "appID": module.params['appId'],
                "privateKey": private_key,
                "apiUri": "https://api.github.com",
            })

            if module.params.get("owner"):
                credentials["owner"] = module.params["owner"]

            payload = {
                "": "0",
                "credentials": credentials
            }

        elif cred_type == 'sshKey':

            # SSH Key credentials require username and private key
            if not module.params['username']:
                module.fail_json(msg="username is required for type 'sshKey'")
            if not module.params['filePath']:
                module.fail_json(msg="filePath is required for type 'sshKey'")
            if not os.path.exists(module.params['filePath']):
                module.fail_json(msg=f"File not found: {module.params['filePath']}")

            try:
                with open(module.params['filePath'], 'r') as f:
                    private_key = f.read().strip()
            except Exception as e:
                module.fail_json(msg=f"Failed to read private key file: {str(e)}")

            credentials.update({
                "$class": "com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey",
                "username": module.params["username"],
                "privateKeySource": {
                    "stapler-class": "com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey$DirectEntryPrivateKeySource",
                    "privateKey": private_key
                },
            })

            if module.params.get("passPhrase"):
                credentials["passPhrase"] = module.params["passPhrase"]

            payload = {
                "": "0",
                "credentials": credentials
            }

        elif cred_type == 'certificate':

            cert = module.params['filePath']
            name, ext = os.path.splitext(cert)

            if ext.lower() in [ '.p12', '.pfx']:

                # certificate requires filePath and password
                if not cert:
                    module.fail_json(msg="filePath is required for type 'certificate'")
                if not os.path.exists(cert):
                    module.fail_json(msg=f"File not found: {cert}")
                if not module.params['password']:
                    module.fail_json(msg="password is required for type 'certificate'")

                try:
                    with open(cert, 'rb') as f:
                        file_content = f.read()
                    uploaded_keystore = base64.b64encode(file_content).decode('utf-8')
                except Exception as e:
                    module.fail_json(msg=f"Failed to read or encode keystore file: {str(e)}")

                credentials.update({
                    "$class": "com.cloudbees.plugins.credentials.impl.CertificateCredentialsImpl",
                    "password": module.params['password'],
                    "keyStoreSource": {
                        "$class": "com.cloudbees.plugins.credentials.impl.CertificateCredentialsImpl$UploadedKeyStoreSource",
                        "uploadedKeystore": uploaded_keystore
                    }
                })

            elif ext.lower() in ['.pem', '.crt']:  # PEM mode

                key_path = module.params.get('privateKeyPath')

                if not cert or not key_path:
                    module.fail_json(msg="Both certificate (filePath) and private key (privateKeyPath) are required for PEM upload")

                if not os.path.exists(cert):
                    module.fail_json(msg=f"Certificate file not found: {cert}")
                if not os.path.exists(key_path):
                    module.fail_json(msg=f"Private key file not found: {key_path}")

                try:
                    with open(cert, 'r') as f:
                        cert_chain = f.read()
                    with open(key_path, 'r') as f:
                        private_key = f.read()
                except Exception as e:
                    module.fail_json(msg=f"Failed to read PEM files: {str(e)}")

                credentials.update({
                    "$class": "com.cloudbees.plugins.credentials.impl.CertificateCredentialsImpl",
                    "keyStoreSource": {
                        "$class": "com.cloudbees.plugins.credentials.impl.CertificateCredentialsImpl$PEMEntryKeyStoreSource",
                        "certChain": cert_chain,
                        "privateKey": private_key
                    }
                })

            else:
                module.fail_json(msg="Unsupported certificate file type. Only .p12, .pfx, .pem or .crt are supported.")

            payload = {
                "": "0",
                "credentials": credentials
            }


        else:
            module.fail_json(msg=f"Unsupported credential type: {cred_type}")
        
        # Build the curl command for add or update
        curl_cmd = build_curl_for_add_or_update(url_suffix_base, payload, module.params['filePath'])

    elif command == 'delete':

        # Delete command requires name
        if not module.params['name']:
            module.fail_json(msg="name is required to delete a credential")

        if module.params['type'] == 'scope':

            # Build the curl command for delete
            curl_cmd = base_curl_cmd.copy()
            curl_cmd.append(f"{module.params['url']}/credentials/store/system/domain/{module.params['name']}/doDelete")
            
        else:
            # Build the curl command for delete
            """ curl_cmd = [
                'curl',
                '-X', 'DELETE',
                '-u', f"{module.params['jenkinsUser']}:{module.params['token']}",
                '-H', f"{crumb_field}:{crumb_value}",
                f"{module.params['url']}/credentials/store/system/domain/_/credential/{module.params['name']}/config.xml"
            ] """
            # Build the curl command for delete
            curl_cmd = base_curl_cmd.copy()
            curl_cmd.append(f"{module.params['url']}/credentials/store/system/domain/_/credential/{module.params['name']}/config.xml")
            
            # replace the 'POST' that follows '-X' with 'DELETE'
            x_index = curl_cmd.index('-X')
            curl_cmd[x_index + 1] = 'DELETE'



    else:
        module.fail_json(msg=f"Unsupported command: {command}")

    try:
        proc = subprocess.run(curl_cmd, capture_output=True, text=True, check=True) # Execute the curl command
        result['changed'] = True
        result['message'] = proc.stdout
        result['debug_curl'] = ' '.join(curl_cmd)

    except subprocess.CalledProcessError as e: # Handle errors
        module.fail_json(
            msg="Failed to execute curl command",
            stderr=e.stderr,
            stdout=e.stdout,
            returncode=e.returncode,
            curl_command=' '.join(curl_cmd)
        )

    module.exit_json(**result)

if __name__ == '__main__':
    run_module()
