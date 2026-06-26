// CD (Deploy stage): set Jenkins job env APP_HOST (EC2 hostname/IP).
// Add SSH credential id "ec2-deploy-ssh" in Jenkins (private key for DEPLOY_USER).
// On EC2: /opt/athena-vi/.env.production must exist (from Secrets Manager / SSM).

pipeline {
    agent any

    environment {
        AWS_REGION = "us-east-1"
        AWS_ACCOUNT_ID = "205091463760"
        ECR_REPOSITORY = "vi-athena-backend"
        ECR_REGISTRY = "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
        IMAGE_TAG = "${BUILD_NUMBER}"
        DEPLOY_DIR = "/opt/athena-vi"
        DEPLOY_USER = "deploy-user"
        APP_HOST = "${env.APP_HOST ?: ''}"
        HEALTH_CHECK_URL = "https://vi.api.lmsathena.com/"
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

                    timeout(time: 5, unit: 'MINUTES') {
                        waitForQualityGate abortPipeline: true
                    }
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
                --exit-code 1 \
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

                docker push \
                ${ECR_REGISTRY}/${ECR_REPOSITORY}:${IMAGE_TAG}

                docker push \
                ${ECR_REGISTRY}/${ECR_REPOSITORY}:latest
                """
            }
        }

        stage('Deploy to Production') {
            when {
                allOf {
                    branch 'main'
                    expression { return env.APP_HOST?.trim() }
                }
            }
            steps {
                sshagent(credentials: ['ec2-deploy-ssh']) {
                    sh """
                    scp -o StrictHostKeyChecking=no \
                      docker-compose.prod.yml \
                      scripts/ec2-deploy.sh \
                      ${DEPLOY_USER}@${APP_HOST}:${DEPLOY_DIR}/

                    ssh -o StrictHostKeyChecking=no ${DEPLOY_USER}@${APP_HOST} \
                      "chmod +x ${DEPLOY_DIR}/ec2-deploy.sh && \
                       ECR_REGISTRY=${ECR_REGISTRY} \
                       ECR_REPOSITORY=${ECR_REPOSITORY} \
                       IMAGE_TAG=${IMAGE_TAG} \
                       AWS_REGION=${AWS_REGION} \
                       DEPLOY_DIR=${DEPLOY_DIR} \
                       ${DEPLOY_DIR}/ec2-deploy.sh"
                    """
                }
            }
        }

        stage('Verify Production') {
            when {
                allOf {
                    branch 'main'
                    expression { return env.APP_HOST?.trim() }
                }
            }
            steps {
                sh """
                curl -sf ${HEALTH_CHECK_URL}
                echo ""
                echo "Public health check passed: ${HEALTH_CHECK_URL}"
                """
            }
        }
    }

    post {
        success {
            echo "========================================"
            echo "Backend CI/CD Pipeline Completed Successfully"
            echo "Docker Image Pushed to Amazon ECR"
            script {
                if (env.BRANCH_NAME == 'main' && env.APP_HOST?.trim()) {
                    echo "Deployed to production (${APP_HOST}) with image tag ${IMAGE_TAG}"
                } else if (env.BRANCH_NAME == 'main') {
                    echo "Image pushed; deploy skipped (set APP_HOST to enable CD on main)"
                } else {
                    echo "CI only (deploy runs on main when APP_HOST is set)"
                }
            }
            echo "========================================"
        }

        failure {
            echo "========================================"
            echo "Backend CI Pipeline Failed"
            echo "Repository is available for debugging"
            echo "========================================"
        }
    }
}
