@Library('eo-jenkins-lib@master') import eo.Utils

pipeline {
    agent any
    options { disableConcurrentBuilds() }
    stages {
        stage('Unit Tests') {
            steps {
                sh 'tox -rv'
            }
            post {
                always {
                    script {
                        utils = new Utils()
                        utils.publish_coverage('coverage.xml')
                        utils.publish_coverage_native('index.html')
                        utils.publish_pylint('pylint.out')
                    }
                    mergeJunitResults()
                }
            }
        }
        stage('Packaging') {
            steps {
                script {
                    if (env.JOB_NAME == 'django-mellon' && env.GIT_BRANCH == 'origin/master') {
                        sh 'sudo -H -u eobuilder /usr/local/bin/eobuilder django-mellon'
                    }
                }
            }
        }
    }
    post {
        always {
            script {
                utils = new Utils()
                utils.mail_notify(currentBuild, env, 'ci+jenkins-django-mellon@entrouvert.org')
            }
        }
        success {
            cleanWs()
        }
    }
}
