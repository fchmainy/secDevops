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
           // env.domain = fqdn.split('.').last(2).join('.')
            env.appName = params.appName
            env.member = params.member

            env.cert = params.certificate
            env.key = params.key

            sh 'echo $cert > $appName.cert'
            sh 'echo $key > $appName.key'

            env.targertURL = params.targetURL
            env.loginURL = params.authenticationURL
            env.method = params.method
            env.app_user = params.usernameField
            env.app_pass = params.passwordField
            env.checkString = params.checkString
            env.dataFormat = params.dataFormat
       
            echo "Data Format: $dataFormat"
            echo "Data_Format: ${dataFormat}"

            withCredentials([[$class: 'UsernamePasswordMultiBinding', credentialsId: 'ipam', usernameVariable: 'USERNAME', passwordVariable: 'PASSWORD']]) {
                env.userIPAM = USERNAME
                env.passIPAM = PASSWORD
            }
   }
   
   stage('certificate validation') {
        sh "echo $key > ${env.BUILD_ID}.key.tmp"
        sh "echo $cert > ${env.BUILD_ID}.cert.tmp"
              
        sh "cat ${env.BUILD_ID}.key.tmp | tr ' ' '\n' | awk '/BEGIN\$/ { printf(\"%s \", \$0); next } 1' | awk '/PRIVATE\$/ { printf(\"%s \", \$0); next } 1' | awk '/END\$/ { printf(\"%s \", \$0); next } 1' |  tee -a ${appName}.key"
        sh "cat ${env.BUILD_ID}.cert.tmp | tr ' ' '\n' | awk '/BEGIN\$/ { printf(\"%s \", \$0); next } 1' | awk '/END\$/ { printf(\"%s \", \$0); next } 1' |  tee -a ${appName}.cert"
      
        // Verify if Key and Certificate modulus match
        def cert_mod = sh (
                script: "openssl x509 -noout -modulus -in ${appName}.cert",
                returnStatus: true
            ) == 0
        def key_mod = sh (
                script: "openssl rsa -noout -modulus -in ${appName}.key",
                returnStatus: true
            ) == 0
        if( "${cert_mod}" != "${key_mod}" ) {
            echo '[FAILURE] Failed to build'
            currentBuild.result = 'FAILURE'
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
                        user: USERNAME,
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
                    playbook: 'importCrypto.yaml', 
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
   
   stage('1st Approval') {
      input 'Proceed to Intensive tests in QA?'
   }
        
  stage('Prepare Crawling and DAST') { 
        //1. Convert the dataformat line so it can used by wget for crawling
        env.wget_dataFormat = sh (
         script: "echo 'username=%U&password=%P&Login=Login' | sed 's/%U/${app_user}/g' | sed 's/%P/${app_pass}/g'",
         returnStdout: true
         ).trim()

        sh "cat base_dast.w3af >> ${env.BUILD_ID}_dast.w3af"

        sh "echo auth detailed >> ${env.BUILD_ID}_dast.w3af"
        sh "echo auth config detailed >> ${env.BUILD_ID}_dast.w3af"
        sh "echo set username $app_user >> ${env.BUILD_ID}_dast.w3af"
        sh "echo set password $app_pass >> ${env.BUILD_ID}_dast.w3af"
        sh "echo set method $method >> ${env.BUILD_ID}_dast.w3af"
        sh "echo set auth_url https://$qaIP$loginURL >> ${env.BUILD_ID}_dast.w3af"
        sh "echo set username_field $app_user >> ${env.BUILD_ID}_dast.w3af"
        sh "echo set password_field $app_pass >> ${env.BUILD_ID}_dast.w3af"
        sh "echo set check_url https://$qaIP$targetURL >> ${env.BUILD_ID}_dast.w3af"
        sh "echo set check_string $checkString >> ${env.BUILD_ID}_dast.w3af"
        sh "echo set data_format '$dataFormat' >> ${env.BUILD_ID}_dast.w3af"
        sh "echo back >> ${env.BUILD_ID}_dast.w3af"
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
        sh "echo exit >> ${env.BUILD_ID}_dast.w3af"
   } 
    
   stage('Crawling & Vulnerability Scan') {
        // Crawling
        //sh "/opt/w3af/w3af_console --no-update -s ${env.BUILD_ID}_crawl.w3af"
        sh "wget --no-check-certificate --bind-address=10.100.26.252 --keep-session-cookies --save-cookies cookies.txt --post-data '$wget_dataFormat' https://$qaIP$loginURL"
        sh "wget --no-check-certificate --bind-address=10.100.26.252 --load-cookies cookies.txt --no-clobber --convert-links --random-wait -r -p --level 1 -E -e robots=off -U FoChromny https://$qaIP$targetURL"
     
        // Vulnerability Assessment
        sh "/opt/w3af/w3af_console --no-update -s ${env.BUILD_ID}_dast.w3af"
   }

   stage('2nd Approval') {
      input 'Proceed to Production?'
   }

   stage('Export WAF Policy and resolve vulnerabilities') {
        withCredentials([[$class: 'UsernamePasswordMultiBinding', credentialsId: 'bigips', usernameVariable: 'USERNAME', passwordVariable: 'PASSWORD']]) {
            ansiblePlaybook(
                colorized: true, 
                inventory: 'hosts.ini', 
                playbook: 'removeASMWildcard.yaml', 
                limit: 'qa:&$zone',
                extras: '-vvv',
                sudoUser: null,
                extraVars: [
                    bigip_username: USERNAME,
                    bigip_password: PASSWORD,
                    appName: appName
                ])
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
                        user: USERNAME,
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
