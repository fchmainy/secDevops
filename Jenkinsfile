#!/usr/bin/env groovy

import groovy.json.JsonOutput

def slackNotificationChannel = "#tests"     

def notifySlack(text, channel, attachments) {
    def slackURL = "https://hooks.slack.com/services/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"
    def jenkinsIcon = 'https://wiki.jenkins-ci.org/download/attachments/2916393/logo.png'

    def payload = JsonOutput.toJson([text: text,
        channel: "#tests",
        username: "webhookbot",
        icon_url: jenkinsIcon
    ])

    sh "curl -X POST --data-urlencode \'payload=${payload}\' ${slackURL}"
}


node {
   stage('Preparation') { 
      git 'https://github.com/fchmainy/jenkinsDemo.git'
   }
   stage('Preparation') { 
      git 'https://github.com/fchmainy/secDevops.git'
   }
   stage('Prepare Crawling and DAST') { 
	   steps {
		sh 'cp base_crawl.w3af >> ${env.BUILD_ID}_crawl.w3af'
        	sh 'echo auth detailed >> ${env.BUILD_ID}_auth.tmp'
		sh 'echo auth config detailed >> ${env.BUILD_ID}_auth.tmp'
		sh 'echo set username ${params.username} >> ${env.BUILD_ID}_auth.tmp'
		sh 'echo set password ${params.password} >> ${env.BUILD_ID}_auth.tmp'
		sh 'echo set method ${params.method} >> ${env.BUILD_ID}_auth.tmp'
		sh 'echo set auth_url ${params.authURL} >> ${env.BUILD_ID}_auth.tmp'
		sh 'echo set username_field ${params.usernameField} >> ${env.BUILD_ID}_auth.tmp'
		sh 'echo set password_field ${params.passwordField} >> ${env.BUILD_ID}_auth.tmp'
		sh 'echo set check_url ${params.targetURL} >> ${env.BUILD_ID}_auth.tmp'
		sh 'echo set check_string ${params.checkString} >> ${env.BUILD_ID}_auth.tmp'
		sh 'echo set data_format ${params.dataFormat} >> ${env.BUILD_ID}_auth.tmp'
		sh 'echo back >> ${env.BUILD_ID}_auth.tmp’
		sh 'echo target >> ${env.BUILD_ID}_auth.tmp'
		sh 'echo set target ${params.targetURL} >> ${env.BUILD_ID}_auth.tmp'
		sh 'echo back >> ${env.BUILD_ID}_auth.tmp’
		sh 'echo cleanup >> ${env.BUILD_ID}_auth.tmp’
		sh 'echo start >> ${env.BUILD_ID}_auth.tmp’
		sh 'cat ${env.BUILD_ID}_auth.tmp >> ${env.BUILD_ID}_crawl.w3af'
   	}
   	steps { 
		sh 'cp base_dast.w3af >> ${env.BUILD_ID}_dast.w3af’
		sh 'cat ${env.BUILD_ID}_auth.tmp >> ${env.BUILD_ID}_dast.w3af'
        	sh 'echo output console,xml_f5asm >> ${env.BUILD_ID}_dast.w3af'
		sh 'echo output config xml_f5asm >> ${env.BUILD_ID}_dast.w3af'
		sh 'echo set output_file ${env.BUILD_ID}_dast.xml >> ${env.BUILD_ID}_dast.w3af'
		sh 'echo set verbose False >> ${env.BUILD_ID}_dast.w3af'
		sh 'echo back >> ${env.BUILD_ID}_dast.w3af'
		sh 'echo back >> ${env.BUILD_ID}_dast.w3af'
		sh 'echo target >> ${env.BUILD_ID}_dast.w3af'
		sh 'echo set target ${params.targetURL} >> ${env.BUILD_ID}_dast.w3af'
		sh 'echo back >> ${env.BUILD_ID}_dast.w3af'
		sh 'echo cleanup >> ${env.BUILD_ID}_dast.w3af'
		sh 'echo start >> ${env.BUILD_ID}_dast.w3af'
   	}
   }

   stage('Testing Ansible Playbooks') {
      //sh "/usr/local/bin/ansible-lint myLab.yaml"
      sh "/usr/local/bin/ansible-review myVSConfig.yaml"
      sh "/usr/local/bin/ansible-review importPolicy.yaml"
      sh "/usr/local/bin/ansible-review exportPolicy.yaml"
      sh "/usr/local/bin/ansible-review importVulnerabilities.yaml"
      sh "/usr/local/bin/ansible-review createASMPolicy.yaml"
   }
   stage('Build in QA') {
	   steps {
       		ansiblePlaybook(
         		colorized: true, 
         		inventory: 'hosts.ini', 
         		playbook: 'myVSConfig.yaml', 
         		extras: '-vvv',
         		sudoUser: null,
         		extraVars: [
            			host: 'qa':&params.zone,
            			bigip_username: 'admin',
            			bigip_password: [value: 'admin', hidden: true],
            			fqdn: params.fqdn,
            			appName: params.appName,
            			member: params.member,
         	])
	   }
	   steps {
       		ansiblePlaybook(
         		colorized: true, 
         		inventory: 'hosts.ini', 
         		playbook: 'createASMPolicy.yaml', 
         		extras: '-vvv',
         		sudoUser: null,
         		extraVars: [
            			host: 'qa':&params.zone,
            			bigip_username: 'admin',
            			bigip_password: [value: 'admin', hidden: true],
            			fqdn: params.fqdn,
            			appName: params.appName,
         		])
	   }
   }
   stage('Crawling') {
      sh "sudo ./w3af_console --no-update -s ${env.BUILD_ID}_crawl.w3af"
   }
   stage('Vulnerability Assessment') {
      sh "sudo ./w3af_console --no-update -s ${env.BUILD_ID}_dast.w3af"
   }
   stage('Approval') {
      input 'Proceed to Production?'
   }
   stage('Export WAF Policy and resolve vulnerabilities') {
       ansiblePlaybook(
         colorized: true, 
         inventory: 'hosts.ini', 
         playbook: 'exportPolicy.yaml', 
         extras: '-vvv',
         sudoUser: null,
         extraVars: [
            host: 'qa':&params.zone,
            bigip_username: 'admin',
            bigip_password: [value: 'admin', hidden: true],
            fqdn: params.fqdn,
            appName: params.appName,
            member: params.member,
         ])
       ansiblePlaybook(
         colorized: true, 
         inventory: 'hosts.ini', 
         playbook: 'importPolicy.yaml', 
         extras: '-vvv',
         sudoUser: null,
         extraVars: [
            host: 'prod':&params.zone,
            bigip_username: 'admin',
            bigip_password: [value: 'admin', hidden: true],
            fqdn: params.fqdn,
            appName: params.appName,
            member: params.member,
         ])
       ansiblePlaybook(
         colorized: true, 
         inventory: 'hosts.ini', 
         playbook: 'importVulnerabilities.yaml', 
         extras: '-vvv',
         sudoUser: null,
         extraVars: [
            host: 'prod':&params.zone,
            bigip_username: 'admin',
            bigip_password: [value: 'admin', hidden: true],
            fqdn: params.fqdn,
            appName: params.appName,
            fileName: ${env.BUILD_ID}_dast.xml,
         ])
   }
   stage('Create Service in Production') {
       ansiblePlaybook(
         colorized: true, 
         inventory: 'hosts.ini', 
         playbook: 'importCrypto.yaml', 
         extras: '-vvv',
         sudoUser: null,
         extraVars: [
            host: 'prod':&params.zone,
            bigip_username: 'admin',
            bigip_password: [value: 'admin', hidden: true],
            fqdn: params.fqdn,
            appName: params.appName,
            member: params.member,
         ])
        ansiblePlaybook(
         colorized: true, 
         inventory: 'hosts.ini', 
         playbook: 'myVSConfig.yaml', 
         extras: '-vvv',
         sudoUser: null,
         extraVars: [
            host: 'prod':&params.zone,
            bigip_username: 'admin',
            bigip_password: [value: 'admin', hidden: true],
            fqdn: params.fqdn,
            appName: params.appName,
            member: params.member,
         ])
       ansiblePlaybook(
         colorized: true, 
         inventory: 'hosts.ini', 
         playbook: 'createASMPolicy.yaml', 
         extras: '-vvv',
         sudoUser: null,
         extraVars: [
            host: 'qa':&params.zone,
            bigip_username: 'admin',
            bigip_password: [value: 'admin', hidden: true],
            fqdn: params.fqdn,
            appName: params.appName,
            member: params.member,
         ])
   }
   stage("Post to Slack") {
        notifySlack("A new service is deployed!", slackNotificationChannel, [])
   }
   
   
   stage('Approval') {
      input 'Proceed to Production?'
   }
}
