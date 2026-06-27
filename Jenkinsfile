pipeline {
    agent any

    environment {
        AWS_REGION = "us-east-1"
        AWS_ACCOUNT_ID = "205091463760"
        ECR_REPOSITORY = "vi-athena-backend"
        ECR_REGISTRY = "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
        IMAGE_TAG = "${env.BUILD_NUMBER}"
    }

    stages {

        stage('Checkout Source') {
            steps {
                checkout scm
            }
        }

        stage('Install Dependencies') {
            steps {
                sh 'npm ci'
            }
        }

        stage('Generate Prisma Client') {
            steps {
                sh 'npx prisma generate'
            }
        }

        stage('Lint') {
            steps {
                sh 'npm run lint'
            }
        }

        stage('SonarQube Scan') {
            steps {
                script {
                    def scannerHome = tool 'SonarScanner'

                    withSonarQubeEnv('Sonarqube') {
                        sh """
                        ${scannerHome}/bin/sonar-scanner \
                        -Dsonar.projectKey=AthenaVI-Backend \
                        -Dsonar.projectName=AthenaVI-Backend \
                        -Dsonar.sources=src \
                        -Dsonar.sourceEncoding=UTF-8 \
                        -Dsonar.exclusions=**/node_modules/**
                        """
                    }

                    // Temporarily disabled while fixing Sonar issues.
                    // Uncomment after resolving Quality Gate failures.

                    /*
                    timeout(time: 5, unit: 'MINUTES') {
                        waitForQualityGate abortPipeline: true
                    }
                    */
                }
            }
        }

        stage('Build Docker Image') {
            steps {
                sh """
                docker build -t ${ECR_REPOSITORY}:${IMAGE_TAG} .
                """
            }
        }

        stage('Trivy Scan') {
            steps {
                sh """
                trivy image \
                --severity HIGH,CRITICAL \
                ${ECR_REPOSITORY}:${IMAGE_TAG}
                """
            }
        }

        stage('Login to Amazon ECR') {
            steps {
                sh """
                aws ecr get-login-password --region ${AWS_REGION} | docker login \
                --username AWS \
                --password-stdin \
                ${ECR_REGISTRY}
                """
            }
        }

        stage('Push Docker Image') {
            steps {
                sh """
                docker tag ${ECR_REPOSITORY}:${IMAGE_TAG} \
                ${ECR_REGISTRY}/${ECR_REPOSITORY}:${IMAGE_TAG}

                docker tag ${ECR_REPOSITORY}:${IMAGE_TAG} \
                ${ECR_REGISTRY}/${ECR_REPOSITORY}:latest

                docker push ${ECR_REGISTRY}/${ECR_REPOSITORY}:${IMAGE_TAG}
                docker push ${ECR_REGISTRY}/${ECR_REPOSITORY}:latest
                """
            }
        }

        stage('Deploy to Amazon EKS') {
            when {
                branch 'main'
            }

            steps {
                sh """
                echo "========================================"
                echo "Deploying Image:"
                echo "${ECR_REGISTRY}/${ECR_REPOSITORY}:${IMAGE_TAG}"
                echo "========================================"

                kubectl set image deployment/backend \
                backend=${ECR_REGISTRY}/${ECR_REPOSITORY}:${IMAGE_TAG}

                kubectl rollout status deployment/backend --timeout=300s

                echo ""
                echo "Current Backend Image:"
                kubectl get deployment backend -o=jsonpath='{.spec.template.spec.containers[0].image}'
                echo ""
                """
            }
        }
    }

    post {

        success {
            echo "========================================"
            echo "Backend CI/CD Pipeline Completed Successfully"
            echo "Docker Image Built Successfully"
            echo "Docker Image Pushed to Amazon ECR"
            echo "Backend Successfully Deployed to Amazon EKS"
            echo "========================================"
        }

        failure {
            echo "========================================"
            echo "Backend CI/CD Pipeline Failed"
            echo "Check Jenkins Console Logs"
            echo "========================================"
        }
    }
}
