## Ansible Jenkins Module: jenkins_credentials

This repository contains development and test resources for the jenkins_credentials Ansible module. The module enables you to manage Jenkins credentials (create, update, delete) and credential domains via the Jenkins HTTP API.

The jenkins_credentials module supports:

<ol>
  <li>Managing all Jenkins credential types:
  <ul>
  <li>userAndPass</li>
  <li>secretText</li>
  <li>sshKey</li>
  <li>certificate</li>
  <li>secretFile</li>
  <li>GitHubApp</li>  
  </ul>
  </li>
    <li>Managing credential domains (create/edit/delete)</li>
    <li>Automating Jenkins credentials as part of CI/CD infrastructure</li>
</ol>

Project Structure

```
ansible_jenkins/
├── jenkins_credentials.py # The main Ansible module
├── certs # Sample certificates for testing
├── add.yml # Test playbook: Add credentials
├── edit.yml # Test playbook: Edit credentials
├── del.yml # Test playbook: Delete credentials
└── README.md # This file
```

Prerequisites

<ul>
  <li>Ansible</li>
  <li>A running Jenkins server with Valid admin user and API token</li>
</ul>

Use the provided test playbooks to try out the module:

<ul>
  <li>add.yml — Add credentials</li>
  <li>edit.yml — Edit existing credentials</li>
  <li>del.yml — Delete credentials</li>
</ul>

Example usage snippet:

```yaml
name: Add Jenkins credential
community.general.jenkins_credentials:
id: "userAndPass-id"
type: "userAndPass"
user: "username"
password: "password"
jenkinsUser: "admin"
token: "your-api-token"
```

For any questions or suggestions feel free to reach out by opening an issue!
