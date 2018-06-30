pipeline {
  agent any
  stages {
    stage('Container Build') {
      parallel {
        stage('Container Build') {
          steps {
            echo 'Building...'
          }
        }
        stage('Building tng-cat...') {
          steps {
            sh 'docker build -t registry.sonata-nfv.eu:5000/tng-cat .'
          }
        }
      }
    }
    stage('Unit Test') {
      parallel {
        stage('Unit Tests') {
          steps {
            echo 'Performing Unit Tests'
          }
        }
        stage('Running Unit Tests') {
          steps {
            sh 'if ! [[ "$(docker inspect -f {{.State.Running}} mongo 2> /dev/null)" == "" ]]; then docker rm -fv mongo ; fi || true'
            sh 'docker run -p 27017:27017 -d --net tango --network-alias mongo --name mongo mongo'
            sh 'sleep 10'
            sh 'docker run --rm=true --net tango --network-alias tng-cat -e RACK_ENV=test -v "$(pwd)/spec/reports:/app/spec/reports" registry.sonata-nfv.eu:5000/tng-cat rake ci:all'
            sh 'if ! [[ "$(docker inspect -f {{.State.Running}} mongo 2> /dev/null)" == "" ]]; then docker rm -fv mongo ; fi || true'
          }
        }
      }
    }
    stage('Containers Publication') {
      parallel {
        stage('Containers Publication') {
          steps {
            echo 'Publication of containers in local registry....'
          }
        }
        stage('Publishing tng-cat') {
          steps {
            sh 'docker push registry.sonata-nfv.eu:5000/tng-cat'
          }
        }
      }
    }


  stage('Deployment in Pre-Integration SP and VnV Environment') {
    parallel {
      stage('Deployment in Pre-Integration SP and VnV Environment') {
        steps {
          echo 'Deploying in pre-integration...'
        }
      }
      stage('Deploying') {
        steps {
          sh 'rm -rf tng-devops || true'
          sh 'git clone https://github.com/sonata-nfv/tng-devops.git'
          dir(path: 'tng-devops') {
           sh 'ansible-playbook roles/sp.yml -i environments -e "target=pre-int-sp component=catalogues"'
           sh 'ansible-playbook roles/vnv.yml -i environments -e "target=pre-int-vnv component=catalogues"'
          }
        }
      }
    }

  }
  stage('Promoting/deploying Containers to Integration SP and VnV Environment') {
    when {
        branch 'master'
    }
    steps {
        echo 'Stage: Promoting containers to integration env'
        sh "pipeline/promote/promote-int.sh"
        sh 'rm -rf tng-devops || true'
        sh 'git clone https://github.com/sonata-nfv/tng-devops.git'
        dir(path: 'tng-devops') {
            sh 'ansible-playbook roles/sp.yml -i environments -e "target=int-sp component=catalogues"'
            sh 'ansible-playbook roles/vnv.yml -i environments -e "target=int-vnv component=catalogues"'
        }
    }
  }
  stage('Promoting containers to integration env') {
    when {
       branch 'master'
    }
    parallel {
        stage('Publishing containers to int') {
            steps {
            echo 'Promoting containers to integration'
            }
         }
        stage('tng-cat') {
            steps {
            sh 'docker tag registry.sonata-nfv.eu:5000/tng-cat:latest registry.sonata-nfv.eu:5000/tng-cat:int'
            sh 'docker push  registry.sonata-nfv.eu:5000/tng-cat:int'
            }
        }
    }
  }
  }
  post {
    always {
      junit(allowEmptyResults: true, testResults: 'spec/reports/*.xml')
    }
     success {
        emailext(from: "jenkins@sonata-nfv.eu",
        to: "pstav@unipi.gr",
        subject: "SUCCESS: ${env.JOB_NAME}/${env.BUILD_ID} (${env.BRANCH_NAME})",
        body: "${env.JOB_URL}")
     }
     failure {
        emailext(from: "jenkins@sonata-nfv.eu",
        to: "pstav@unipi.gr",
        subject: "FAILURE: ${env.JOB_NAME}/${env.BUILD_ID} (${env.BRANCH_NAME})",
        body: "${env.JOB_URL}")
        }
  }
}
