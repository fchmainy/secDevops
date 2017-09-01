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
            git 'https://github.com/fchmainy/secDevops.git'   
       
            // Setting up environment variables
            echo "setting up variables..."
            env.zone = params.zones
            env.fqdn = params.fqdn
            env.appName = params.appName
            env.member = params.member

            env.cert = params.certificate
            env.key = params.key

            sh 'echo $cert > $appName.cert'
            sh 'echo $key > $appName.key'

            env.targertURL = params.targetURL
            env.loginURL = params.loginURL
            env.method = params.method
            env.app_user = params.usernameField
            env.app_pass = params.passwordField
            env.checkString = params.checkString
            env.dataFormat = params.dataFormat

            withCredentials([[$class: 'UsernamePasswordMultiBinding', credentialsId: 'ipam', usernameVariable: 'USERNAME', passwordVariable: 'PASSWORD']]) {
                env.userIPAM = USERNAME
                env.passIPAM = PASSWORD
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
            // Request IP Address for IPAM
            withCredentials([[$class: 'UsernamePasswordMultiBinding', credentialsId: 'ipam', usernameVariable: 'USERNAME', passwordVariable: 'PASSWORD']]) {
              ansiblePlaybook(
                colorized: true, 
                inventory: 'hosts.ini', 
                playbook: 'getIP.yaml', 
                limit: 'ipam',
                extras: '-vvv',
                sudoUser: null,
                extraVars: [
                        username: USERNAME,
                        password: PASSWORD,
                        fqdn: fqdn,
                        outputFile: "${env.WORKSPACE}/${appName}_qa_${env.BUILD_ID}.ip",
                        member: member
              ])
            }
       
            // Record the VS IP Address
            env.qaIP = readFile "${env.WORKSPACE}/${appName}_qa_${env.BUILD_ID}.ip" 
            
            // Create LB Config 
            withCredentials([[$class: 'UsernamePasswordMultiBinding', credentialsId: 'bigips', usernameVariable: 'USERNAME', passwordVariable: 'PASSWORD']]) {
              ansiblePlaybook(
                colorized: true, 
                inventory: 'hosts.ini', 
                playbook: 'myVSConfig.yaml', 
                limit: 'qa:&$zone',
                extras: '-vvv',
                sudoUser: null,
                extraVars: [
                        bigip_username: USERNAME,
                        bigip_password: PASSWORD,
                        fqdn: fqdn,
                        appName: appName,
                        vsIP: qaIP,
                        member: member
              ])
            }
           
          withCredentials([[$class: 'UsernamePasswordMultiBinding', credentialsId: 'bigips', usernameVariable: 'USERNAME', passwordVariable: 'PASSWORD']]) {
            ansiblePlaybook(
                colorized: true, 
                inventory: 'hosts.ini', 
                playbook: 'createASMPolicy.yaml', 
                limit: 'qa:&$zone',
                extras: '-vvv',
                sudoUser: null,
                extraVars: [
                        bigip_username: USERNAME,
                        bigip_password: PASSWORD,
                        fqdn: fqdn,
                        appName: appName
                ])
          }
       
   }
    
   stage('Prepare Crawling and DAST') { 
        sh "cp base_crawl.w3af ${env.BUILD_ID}_crawl.w3af"
        sh "echo auth detailed >> ${env.BUILD_ID}_auth.tmp"
        sh "echo auth config detailed >> ${env.BUILD_ID}_auth.tmp"
        sh "echo set username $app_user >> ${env.BUILD_ID}_auth.tmp"
        sh "echo set password $app_pass >> ${env.BUILD_ID}_auth.tmp"
        sh "echo set method $method >> ${env.BUILD_ID}_auth.tmp"
        sh "echo set auth_url https://$qaIP$loginURL >> ${env.BUILD_ID}_auth.tmp"
        sh "echo set username_field $app_user >> ${env.BUILD_ID}_auth.tmp"
        sh "echo set password_field $app_pass >> ${env.BUILD_ID}_auth.tmp"
        sh "echo set check_url https://$qaIP$targetURL >> ${env.BUILD_ID}_auth.tmp"
        sh "echo set check_string $checkString >> ${env.BUILD_ID}_auth.tmp"
        sh "echo set data_format $dataFormat >> ${env.BUILD_ID}_auth.tmp"
        sh "echo back >> ${env.BUILD_ID}_auth.tmp"
        sh "echo target >> ${env.BUILD_ID}_auth.tmp"
        sh "echo set target https://$qaIP$targetURL >> ${env.BUILD_ID}_auth.tmp"
        sh "echo back >> ${env.BUILD_ID}_auth.tmp"
        sh "echo cleanup >> ${env.BUILD_ID}_auth.tmp"
        sh "echo start >> ${env.BUILD_ID}_auth.tmp"
        sh "cat ${env.BUILD_ID}_auth.tmp >> ${env.BUILD_ID}_crawl.w3af"

        sh "cp base_dast.w3af ${env.BUILD_ID}_dast.w3af"
        sh "cat ${env.BUILD_ID}_auth.tmp >> ${env.BUILD_ID}_dast.w3af"
        sh "echo output console,xml_f5asm >> ${env.BUILD_ID}_dast.w3af"
        sh "echo output config xml_f5asm >> ${env.BUILD_ID}_dast.w3af"
        sh "echo set output_file ${env.BUILD_ID}_dast.xml >> ${env.BUILD_ID}_dast.w3af"
        sh "echo set verbose False >> ${env.BUILD_ID}_dast.w3af"
        sh "echo back >> ${env.BUILD_ID}_dast.w3af"
        sh "echo back >> ${env.BUILD_ID}_dast.w3af"
        sh "echo target >> ${env.BUILD_ID}_dast.w3af"
        sh "echo set target https://$qaIP$targetURL >> ${env.BUILD_ID}_dast.w3af"
        sh "echo back >> ${env.BUILD_ID}_dast.w3af"
        sh "echo cleanup >> ${env.BUILD_ID}_dast.w3af"
        sh "echo start >> ${env.BUILD_ID}_dast.w3af"
   } 
    
   stage('Crawling & Vulnerability Scan') {
        // Crawling
        sh "sudo ./w3af_console --no-update -s ${env.BUILD_ID}_crawl.w3af"
        // Vulnerability Assessment
        sh "sudo ./w3af_console --no-update -s ${env.BUILD_ID}_dast.w3af"
   }

   stage('Approval') {
      input 'Proceed to Production?'
   }

   stage('Export WAF Policy and resolve vulnerabilities') {
        withCredentials([[$class: 'UsernamePasswordMultiBinding', credentialsId: 'bigips', usernameVariable: 'USERNAME', passwordVariable: 'PASSWORD']]) {
            ansiblePlaybook(
                colorized: true, 
                inventory: 'hosts.ini', 
                playbook: 'exportPolicy.yaml', 
                limit: 'qa:&$zone',
                extras: '-vvv',
                sudoUser: null,
                extraVars: [
                    bigip_username: USERNAME,
                    bigip_password: PASSWORD,
                    fqdn: fqdn,
                    appName: appName
                ])
            ansiblePlaybook(
                colorized: true, 
                inventory: 'hosts.ini', 
                playbook: 'importPolicy.yaml', 
                limit: 'prod:&$zone',
                extras: '-vvv',
                sudoUser: null,
                extraVars: [
                    host: 'prod:&$zone',
                    bigip_username: USERNAME,
                    bigip_password: PASSWORD,
                    fqdn: fqdn,
                    appName: appName
                ])
            ansiblePlaybook(
                colorized: true, 
                inventory: 'hosts.ini', 
                playbook: 'importVulnerabilities.yaml', 
                limit: 'prod:&$zone',
                extras: '-vvv',
                sudoUser: null,
                extraVars: [
                    bigip_username: USERNAME,
                    bigip_password: PASSWORD,
                    fqdn: fqdn,
                    appName: appName,
                    fileName: "${env.BUILD_ID}_dast.xml"
            ])
        }
   }
   stage('Create Service in Production') {
            // Request IP Address for IPAM
            withCredentials([[$class: 'UsernamePasswordMultiBinding', credentialsId: 'ipam', usernameVariable: 'USERNAME', passwordVariable: 'PASSWORD']]) {
              ansiblePlaybook(
                colorized: true, 
                inventory: 'hosts.ini', 
                playbook: 'getIP.yaml', 
                limit: 'ipam',
                extras: '-vvv',
                sudoUser: null,
                extraVars: [
                        username: USERNAME,
                        password: PASSWORD,
                        fqdn: fqdn,
                        outputFile: "${env.WORKSPACE}/${appName}_prod_${env.BUILD_ID}.ip",
                        member: member
              ])
            }
       
            // Record the VS IP Address
            env.prodIP = readFile "${env.WORKSPACE}/${appName}_prod_${env.BUILD_ID}.ip" 
            
            withCredentials([[$class: 'UsernamePasswordMultiBinding', credentialsId: 'bigips', usernameVariable: 'USERNAME', passwordVariable: 'PASSWORD']]) {
               ansiblePlaybook(
                    colorized: true, 
                    inventory: 'hosts.ini', 
                    playbook: 'importCrypto.yaml', 
                    limit: 'prod:&$zone',
                    extras: '-vvv',
                    sudoUser: null,
                    extraVars: [
                        bigip_username: USERNAME,
                        bigip_password: PASSWORD,
                        fqdn: fqdn,
                        appName: appName
                ])
                ansiblePlaybook(
                    colorized: true, 
                    inventory: 'hosts.ini', 
                    playbook: 'myVSConfig.yaml', 
                    limit: 'prod:&$zone',
                    extras: '-vvv',
                    sudoUser: null,
                    extraVars: [
                        bigip_username: USERNAME,
                        bigip_password: PASSWORD,
                        fqdn: fqdn,
                        vsIP: prodIP,
                        appName: appName,
                        member: member
                ])
                ansiblePlaybook(
                    colorized: true, 
                    inventory: 'hosts.ini', 
                    playbook: 'attachASMPolicy.yaml', 
                    limit: 'prod:&$zone',
                    extras: '-vvv',
                    sudoUser: null,
                    extraVars: [
                        bigip_username: USERNAME,
                        bigip_password: PASSWORD,
                        fqdn: fqdn,
                        appName: appName
                ])
            }
   }
   stage("Post to Slack") {
        notifySlack("A new service is deployed!", slackNotificationChannel, [])
   }
   
   
   stage('Approval') {
      input 'Proceed to Production?'
   }
}
