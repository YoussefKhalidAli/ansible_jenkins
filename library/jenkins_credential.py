# -*- coding: utf-8 -*-
# Copyright: (c) 2024, Youssef yossofwd@google.com
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: jenkins_credential
short_description: Manage Jenkins credentials and domains via API
description:
  - This module allows managing Jenkins credentials and domain scopes via Jenkins HTTP API.
  - You can create, update, and delete different credential types such as username/password, secret text, SSH key, certificates, GitHub App, and scoped domains.
  - For scoped credentials, it supports hostname, hostname:port, path, and scheme-based restrictions.
version_added: "1.0"
author:
  - Youssef (@YoussefKhalidAli)
options:
  name:
    description:
      - The ID or name of the Jenkins credential or domain.
    required: true
    type: str
  type:
    description:
      - Type of the credential or action.
    choices:
      - userAndPass
      - file
      - text
      - githubApp
      - sshKey
      - certificate
      - scope
    type: str
  command:
    description:
      - The operation to perform.
    choices: [add, delete, update]
    default: add
    type: str
  scope:
    description:
      - Jenkins credential domain scope.
    type: str
    default: '_' (global)
  url:
    description:
      - Jenkins server URL.
    type: str
    default: http://localhost:8080
  jenkinsUser:
    description:
      - Jenkins user for authentication.
    required: true
    type: str
  token:
    description:
      - Jenkins API token.
    required: true
    type: str
  description:
    description:
      - Optional description of the credential or domain.
    type: str
  username:
    description:
      - Username for credentials that require it (e.g., sshKey, userAndPass).
    type: str
  password:
    description:
      - Password or secret text.
    type: str
  text:
    description:
      - Secret text (used in "text" type).
    type: str
  appId:
    description:
      - GitHub App ID.
    type: str
  owner:
    description:
      - GitHub App owner.
    type: str
  filePath:
    description:
      - File path to secret (e.g., private key, certificate).
    type: str
  privateKeyPath:
    description:
      - Path to private key file for PEM certificates.
    type: str
  passPhrase:
    description:
      - SSH passphrase.
    type: str
  incHostName:
    description:
      - List of hostnames to include in scope.
    type: list
    elements: str
  excHostName:
    description:
      - List of hostnames to exclude from scope.
    type: list
    elements: str
  incHostNamePort:
    description:
      - List of host:port to include in scope.
    type: list
    elements: str
  excHostNamePort:
    description:
      - List of host:port to exclude from scope.
    type: list
    elements: str
  incPath:
    description:
      - List of URL paths to include.
    type: list
    elements: str
  excPath:
    description:
      - List of URL paths to exclude.
    type: list
    elements: str
  schemes:
    description:
      - List of schemes (e.g., http, https) to match.
    type: list
    elements: str
'''

EXAMPLES = r'''
    - name: Add CUSTOM scope credential
      jenkins_credential:
        name: "CUSTOM"
        type: "scope"
        jenkinsUser: "admin"
        token: "token"
        description: "Custom scope credential"
        incPath:
          - "include/path"
          - "include/path2"
        excPath:
          - "exclude/path"
          - "exclude/path2"
        incHostName:
          - "included-hostname"
          - "included-hostname2"
        excHostName:
          - "excluded-hostname"
          - "excluded-hostname2"
        schemes:
          - "http"
          - "https"
        incHostNamePort:
          - "included-hostname:7000"
          - "included-hostname2:7000"
        excHostNamePort:
          - "excluded-hostname:7000"
          - "excluded-hostname2:7000"

    - name: Add userAndPass credential
      jenkins_credential:
        scope: "CUSTOM"
        name: "userpass-id"
        type: "userAndPass"
        jenkinsUser: "admin"
        token: "token"
        description: "User and password credential"
        username: "user1"
        password: "pass1"

    - name: Add file credential
      jenkins_credential:
        name: "file-id"
        type: "file"
        jenkinsUser: "admin"
        token: "token"
        description: "File credential"
        filePath: "my-secret.pem"

    - name: Add text credential
      jenkins_credential:
        name: "text-id"
        type: "text"
        jenkinsUser: "admin"
        token: "token"
        description: "Text credential"
        text: "mysecrettext"

    - name: Add githubApp credential
      jenkins_credential:
        name: "githubapp-id"
        type: "githubApp"
        jenkinsUser: "admin"
        token: "token"
        description: "GitHub App credential"
        appId: "12345"
        filePath: "my-secret.pem"
        owner: "github_owner"

    - name: Add sshKey credential
      jenkins_credential:
        name: "sshkey-id"
        type: "sshKey"
        jenkinsUser: "admin"
        token: "token"
        description: "SSH key credential"
        username: "sshuser"
        filePath: "my-secret.pem"

    - name: Add certificate credential (p12)
      jenkins_credential:
        name: "certificate-id"
        type: "certificate"
        jenkinsUser: "admin"
        token: "token"
        description: "Certificate credential"
        password: "12345678901234"
        filePath: "certificate.p12"

    - name: Add certificate credential (pem)
      jenkins_credential:
        name: "certificate-id-pem"
        type: "certificate"
        jenkinsUser: "admin"
        token: "token"
        description: "Certificate credential (pem)"
        filePath: "cert.pem"
        privateKeyPath: "private.key"
'''

RETURN = r'''
changed:
    description: Whether a change was made.
    type: bool
    returned: always
message:
    description: Message from Jenkins or the result of the operation.
    type: str
    returned: always
debug_curl:
    description: The full curl command used (for debugging).
    type: str
    returned: on success
stderr:
    description: Standard error if the curl command fails.
    type: str
    returned: on failure
stdout:
    description: Standard output if the curl command fails.
    type: str
    returned: on failure
curl_command:
    description: The full curl command that failed.
    type: str
    returned: on failure
'''

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
    
# Function to check if credential exists
def credential_exists(url, scope, name, user, token):
    check_url = f"{url}/credentials/store/system/domain/{scope}/credential/{name}/api/json"
    auth = f"{user}:{token}".encode('utf-8')
    b64_auth = base64.b64encode(auth).decode('utf-8')
    headers = {
        "Authorization": f"Basic {b64_auth}",
        "Accept": "application/json"
    }

    req = urllib.request.Request(check_url, headers=headers)

    try:
        with urllib.request.urlopen(req) as resp:
            if resp.status == 200:
                return True
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False
        else:
            raise
    return False

# Function to check if domain (scope) exists
def domain_exists(url, name, user, token):
    check_url = f"{url}/credentials/store/system/domain/{name}/api/json"
    auth = f"{user}:{token}".encode('utf-8')
    b64_auth = base64.b64encode(auth).decode('utf-8')
    headers = {
        "Authorization": f"Basic {b64_auth}",
        "Accept": "application/json"
    }

    req = urllib.request.Request(check_url, headers=headers)
    try:
        with urllib.request.urlopen(req) as resp:
            if resp.status == 200:
                return True
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False
        else:
            raise
    return False

# Helper to build the payload and curl command for add or update
def build_curl_for_add_or_update(base_curl_cmd, url, url_suffix, payload_json, file_path=None):
    
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
    cmd.append(f"{url}{url_suffix}")
    
    return cmd

# Main function to run the Ansible module
def run_module():
    
    module = AnsibleModule(
        argument_spec=dict(
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

        # Scope specifications parameters
        incHostName=dict(type='list', required=False), # Include hostname for scope type
        excHostName=dict(type='list', required=False), # Exclude hostname for scope type
        incHostNamePort=dict(type='list', required=False), # Include hostname and port for scope type
        excHostNamePort=dict(type='list', required=False), # Exclude hostname and port for scope type
        incPath=dict(type='list', required=False), # Include path for scope type
        excPath=dict(type='list', required=False), # Exclude path for scope type
        schemes=dict(type='list', required=False), # Schemes for scope type
        ),
        supports_check_mode=True,
    )

    # Parameters
    name = module.params['name']
    type = module.params['type']
    command = module.params['command']
    scope = module.params['scope']
    url = module.params['url']
    jenkinsUser = module.params['jenkinsUser']
    token = module.params['token']
    description = module.params['description']
    username = module.params['username']
    password = module.params['password']
    filePath = module.params['filePath']
    text = module.params['text']
    appId = module.params['appId']
    owner = module.params['owner']
    passPhrase = module.params['passPhrase']
    privateKeyPath = module.params['privateKeyPath']
    incHostName = module.params['incHostName']
    excHostName = module.params['excHostName']
    incHostNamePort = module.params['incHostNamePort']
    excHostNamePort = module.params['excHostNamePort']
    incPath = module.params['incPath']
    excPath = module.params['excPath']
    schemes = module.params['schemes']

    # Get the crumb for CSRF protection
    crumb_field, crumb_value = get_jenkins_crumb(url, jenkinsUser, token)
    if not crumb_field or not crumb_value:
        module.fail_json(msg="Failed to fetch Jenkins crumb. Check Jenkins URL and credentials.")

    result = dict(
        changed=False,
        message='',
    )

    credentials = {
        "id": name,
        "description": description,
    }

    # Base curl command common params
    base_curl_cmd = [
        'curl',
        '-u', f"{jenkinsUser}:{token}",
        '-H', f"{crumb_field}:{crumb_value}",
        '-X', 'POST',
    ]

    if not type == 'scope':

        does_credential_exist = credential_exists(url, scope, name, jenkinsUser, token)
        # Check if the credential already exists
        if does_credential_exist and  command == 'add':
            result['message'] = f"Credential {name} already exists."
            module.exit_json(**result)
        
        # Check if the credential doesn't exist
        elif not does_credential_exist and command == 'delete':
            result['message'] = f"Credential {name} doesn't exist."
            module.exit_json(**result)

    elif type == 'scope':

        does_domain_exist = domain_exists(url, name, jenkinsUser, token)
        # Check if the domain already exists
        if does_domain_exist and command == 'add':
            result['changed'] = False
            result['message'] = f"Domain {name} already exists."
            module.exit_json(**result)

        # Check if the domain doesn't exist
        elif not does_domain_exist and command == 'delete':
            result['changed'] = False
            result['message'] = f"Domain {name} doesn't exist."
            module.exit_json(**result)

    if command in ['add', 'update']:
        # Check if credential type is provided
        if type == None:
            module.fail_json(msg="Credential type is required for add or update")
            
        url_suffix_base = f"/credentials/store/system/domain/{scope}/createCredentials"

        # If updating, we need to delete the existing credential first
        if command == 'update':
            delete_cmd = [
            'curl',
            '-X', 'DELETE',
            '-u', f"{jenkinsUser}:{token}",
            '-H', f"{crumb_field}:{crumb_value}",
            f"{url}/credentials/store/system/domain/_/credential/{name}/config.xml"
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
            
        if type == 'scope':

            specifications = []

            # Create a domain in Jenkins
            if incHostName or excHostName:
                specifications.append({
                        "stapler-class": "com.cloudbees.plugins.credentials.domains.HostnameSpecification",
                        "includes": ",".join(incHostName),
                        "excludes": ",".join(excHostName)
                    })
            
            if incHostNamePort or excHostNamePort:
                specifications.append({
                        "stapler-class": "com.cloudbees.plugins.credentials.domains.HostnamePortSpecification",
                        "includes": ",".join(incHostNamePort),
                        "excludes": ",".join(excHostNamePort)
                    })
                
            if schemes:
                specifications.append({
                    "stapler-class": "com.cloudbees.plugins.credentials.domains.SchemeSpecification",
                    "schemes": ",".join(schemes)
                },)

            if incPath or excPath:
                specifications.append({
                    "stapler-class": "com.cloudbees.plugins.credentials.domains.PathSpecification",
                    "includes": ",".join(incPath),
                    "excludes": ",".join(excPath)
                })

            payload = {
                "name": name,
                "description": description,
                "specifications": specifications,
            }

            url_suffix_base = "/credentials/store/system/createDomain"

        # For each credential type build the credentials dict & payload then build curl_cmd
        elif type == 'userAndPass':

            # userAndPass requires username and password
            if not username or not password:
                module.fail_json(msg="username and password are required for type 'userAndPass'")

            credentials.update({
                "$class": "com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl",
                "username": username,
                "password": password
            })

            payload = {
                "": "0",
                "credentials": credentials
            }

        elif type == 'file':

            # file requires filePath
            if not filePath:
                module.fail_json(msg="filePath is required for type 'file'")
            if not os.path.exists(filePath):
                module.fail_json(msg=f"File not found: {filePath}")

            credentials.update({
                "$class": "org.jenkinsci.plugins.plaincredentials.impl.FileCredentialsImpl",
                "file": "file0",
                "fileName": os.path.basename(filePath),
            })

            payload = {
                "": "0",
                "credentials": credentials
            }

        elif type == 'text':
            if not text:
                module.fail_json(msg="text is required for type 'text'")

            credentials.update({
                "$class": "org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl",
                "secret": text,
            })

            payload = {
                "": "0",
                "credentials": credentials
            }

        elif type == 'githubApp':

            # GitHub App credentials require appId and private key
            if not appId:
                module.fail_json(msg="appId is required for type 'githubApp'")
            if not filePath:
                module.fail_json(msg="filePath is required for type 'githubApp'")
            if not os.path.exists(filePath):
                module.fail_json(msg=f"File not found: {filePath}")

            try:
                with open(filePath, 'r') as f:
                    private_key = f.read().strip()
            except Exception as e:
                module.fail_json(msg=f"Failed to read private key file: {str(e)}")

            credentials.update({
                "$class": "org.jenkinsci.plugins.github_branch_source.GitHubAppCredentials",
                "appID": appId,
                "privateKey": private_key,
                "apiUri": "https://api.github.com",
            })

            if owner:
                credentials["owner"] = owner

            payload = {
                "": "0",
                "credentials": credentials
            }

        elif type == 'sshKey':

            # SSH Key credentials require username and private key
            if not username:
                module.fail_json(msg="username is required for type 'sshKey'")
            if not filePath:
                module.fail_json(msg="filePath is required for type 'sshKey'")
            if not os.path.exists(filePath):
                module.fail_json(msg=f"File not found: {filePath}")

            try:
                with open(filePath, 'r') as f:
                    private_key = f.read().strip()
            except Exception as e:
                module.fail_json(msg=f"Failed to read private key file: {str(e)}")

            credentials.update({
                "$class": "com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey",
                "username": username,
                "privateKeySource": {
                    "stapler-class": "com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey$DirectEntryPrivateKeySource",
                    "privateKey": private_key
                },
            })

            if passPhrase:
                credentials["passPhrase"] = passPhrase

            payload = {
                "": "0",
                "credentials": credentials
            }

        elif type == 'certificate':

            cert = filePath
            name, ext = os.path.splitext(cert)

            if ext.lower() in [ '.p12', '.pfx']:

                # certificate requires filePath and password
                if not cert:
                    module.fail_json(msg="filePath is required for type 'certificate'")
                if not os.path.exists(cert):
                    module.fail_json(msg=f"File not found: {cert}")
                if not password:
                    module.fail_json(msg="password is required for type 'certificate'")

                try:
                    with open(cert, 'rb') as f:
                        file_content = f.read()
                    uploaded_keystore = base64.b64encode(file_content).decode('utf-8')
                except Exception as e:
                    module.fail_json(msg=f"Failed to read or encode keystore file: {str(e)}")

                credentials.update({
                    "$class": "com.cloudbees.plugins.credentials.impl.CertificateCredentialsImpl",
                    "password": password,
                    "keyStoreSource": {
                        "$class": "com.cloudbees.plugins.credentials.impl.CertificateCredentialsImpl$UploadedKeyStoreSource",
                        "uploadedKeystore": uploaded_keystore
                    }
                })

            elif ext.lower() in ['.pem', '.crt']:  # PEM mode

                if not cert or not privateKeyPath:
                    module.fail_json(msg="Both certificate (filePath) and private key (privateKeyPath) are required for PEM upload")

                if not os.path.exists(cert):
                    module.fail_json(msg=f"Certificate file not found: {cert}")
                if not os.path.exists(privateKeyPath):
                    module.fail_json(msg=f"Private key file not found: {privateKeyPath}")

                try:
                    with open(cert, 'r') as f:
                        cert_chain = f.read()
                    with open(privateKeyPath, 'r') as f:
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
            module.fail_json(msg=f"Unsupported credential type: {type}")
        
        # Build the curl command for add or update
        curl_cmd = build_curl_for_add_or_update(base_curl_cmd, url, url_suffix_base, payload, filePath)

    elif command == 'delete':

        # Delete command requires name
        if not name:
            module.fail_json(msg="name is required to delete a credential")

        if type == 'scope':

            # Build the curl command for delete
            curl_cmd = base_curl_cmd.copy()
            curl_cmd.append(f"{url}/credentials/store/system/domain/{name}/doDelete")
            
        else:
            # Build the curl command for delete
            """ curl_cmd = [
                'curl',
                '-X', 'DELETE',
                '-u', f"{jenkinsUser}:{token}",
                '-H', f"{crumb_field}:{crumb_value}",
                f"{url}/credentials/store/system/domain/_/credential/{name}/config.xml"
            ] """
            # Build the curl command for delete
            curl_cmd = base_curl_cmd.copy()
            curl_cmd.append(f"{url}/credentials/store/system/domain/{scope}/credential/{name}/config.xml")
            
            # replace the 'POST' that follows '-X' with 'DELETE'
            x_index = curl_cmd.index('-X')
            curl_cmd[x_index + 1] = 'DELETE'



    else:
        module.fail_json(msg=f"Unsupported command: {command}")

    try:
        proc = subprocess.run(curl_cmd, capture_output=True, text=True, check=True) # Execute the curl command
        result['changed'] = True
        result['debug_curl'] = ' '.join(curl_cmd)
        result['message'] = proc.stdout
        if proc.stdout and not type == 'scope':
            module.fail_json(msg=f"Unexpected output from curl command: {proc.stdout}", debug_curl=' '.join(curl_cmd))

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
