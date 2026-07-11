pipeline {
    agent any

    environment {
        AWS_REGION = 'us-east-1'

        AWS_ACCOUNT_ID = '205091463760'
        ECR_REPOSITORY = 'vi-athena-backend'
        ECR_REGISTRY = "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"

        IMAGE_TAG = "${BUILD_NUMBER}"

        PATH = "/usr/local/bin:/usr/bin:/bin:$PATH"
    }

    options {
        timestamps()
    }

    stages {

        stage('Checkout Source') {
            steps {
                checkout scm
            }
        }

        stage('Install Dependencies') {
            steps {
                sh '''
                set -e
                npm install
                '''
            }
        }

        stage('Generate Prisma Client') {
            steps {
                sh '''
                set -e
                npx prisma generate
                '''
            }
        }

        stage('SonarQube Scan') {
            steps {
                script {

                    def scannerHome = tool 'SonarScanner'

                    withSonarQubeEnv('Sonarqube') {

                        sh """
                        set -e

                        ${scannerHome}/bin/sonar-scanner \
                        -Dsonar.projectKey=AthenaVI-Backend \
                        -Dsonar.projectName=AthenaVI-Backend \
                        -Dsonar.sources=src \
                        -Dsonar.sourceEncoding=UTF-8
                        """
                    }
                }
            }
        }

        stage('Build Docker Image') {
            steps {
                sh """
                set -e

                docker build \
                -t ${ECR_REPOSITORY}:${IMAGE_TAG} .
                """
            }
        }

        stage('Trivy Scan') {
            steps {
                sh """
                set -e

                trivy image \
                --severity HIGH,CRITICAL \
                --exit-code 0 \
                ${ECR_REPOSITORY}:${IMAGE_TAG}
                """
            }
        }

        stage('Login to Amazon ECR') {
            steps {
                sh """
                set -e

                aws ecr get-login-password --region ${AWS_REGION} | \
                docker login \
                --username AWS \
                --password-stdin ${ECR_REGISTRY}
                """
            }
        }

        stage('Push Docker Image') {
            steps {
                sh """
                set -e

                docker tag ${ECR_REPOSITORY}:${IMAGE_TAG} ${ECR_REGISTRY}/${ECR_REPOSITORY}:${IMAGE_TAG}

                docker tag ${ECR_REPOSITORY}:${IMAGE_TAG} ${ECR_REGISTRY}/${ECR_REPOSITORY}:latest

                docker push ${ECR_REGISTRY}/${ECR_REPOSITORY}:${IMAGE_TAG}

                docker push ${ECR_REGISTRY}/${ECR_REPOSITORY}:latest
                """
            }
        }

        stage('Run Prisma Migrations') {
            steps {
                sh """
                set -e

                export DATABASE_URL='postgresql://postgres:Viathena12345678!@vi-athena-postgres.cudsmc82cvxc.us-east-1.rds.amazonaws.com:5432/viathena?sslmode=require'

                npx prisma migrate deploy
                """
            }
        }

        stage('Deploy to Amazon EKS') {
            steps {
                sh """
                set -e

                aws eks update-kubeconfig \
                  --region ${AWS_REGION} \
                  --name vi-athena-eks

                kubectl set image deployment/backend \
                backend=${ECR_REGISTRY}/${ECR_REPOSITORY}:${IMAGE_TAG}

                if ! kubectl rollout status deployment/backend --timeout=300s; then
                    echo "Deployment failed. Rolling back..."
                    kubectl rollout undo deployment/backend
                    exit 1
                fi

                echo ""
                echo "========== Running Pods ========="
                kubectl get pods

                echo ""
                echo "========== Deployments ========="
                kubectl get deployment

                echo ""
                echo "========== Services =========="
                kubectl get svc

                echo ""
                echo "========== Rollout History ========="
                kubectl rollout history deployment/backend

                echo ""
                echo "========== Current Image ========="
                kubectl get deployment backend \
                -o=jsonpath='{.spec.template.spec.containers[0].image}'

                echo ""
            """
            }
        }
    }

    post {

        always {
            cleanWs()
        }

        success {

            echo "====================================="
            echo "Backend CI/CD Pipeline Completed Successfully"
            echo "Docker Image Built Successfully"
            echo "Docker Image Pushed to Amazon ECR"
            echo "Prisma Migrations Applied Successfully"
            echo "Backend Successfully Deployed to Amazon EKS"
            echo "====================================="
        }

        failure {

            echo "========================================"
            echo "Backend CI/CD Pipeline Failed"
            echo "Deployment Rolled Back (if rollout failed)"
            echo "========================================"
        }
    }
}
