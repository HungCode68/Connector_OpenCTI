pipeline {
    agent any

    // Định nghĩa các biến môi trường
    environment {
        DOCKER_IMAGE = 'opencti-mthcht-connector'
        CONTAINER_NAME = 'threat-intel-connector'
    }

    stages {
        stage('Checkout Code') {
            steps {
                // Lấy code mới nhất từ GitHub
                checkout scm
            }
        }

        stage('Build Docker Image') {
            steps {
                // Đóng gói code thành Docker Image
                sh 'docker build -t ${DOCKER_IMAGE}:latest .'
            }
        }

        stage('Run/Deploy Connector') {
            steps {
                // Xóa container cũ nếu đang chạy
                sh 'docker rm -f ${CONTAINER_NAME} || true'
                
                // Lấy credentials đã lưu trên Jenkins và bơm vào container
                withCredentials([
                    string(credentialsId: 'OPENCTI_TOKEN_SECRET', variable: 'ENV_OPENCTI_TOKEN')
                ]) {
                    // Chạy Docker và truyền biến môi trường vào qua cờ -e
                    sh '''
                    docker run --name ${CONTAINER_NAME} --rm \
                      -e OPENCTI_URL="http://52.1.238.11:8080/" \
                      -e OPENCTI_TOKEN="${ENV_OPENCTI_TOKEN}" \
                      ${DOCKER_IMAGE}:latest
                    '''
                }
            }
        }
    }

    post {
        always {
            echo 'Quy trình triển khai đã hoàn tất!'
            // Có thể cấu hình gửi thông báo qua Telegram/Slack ở đây
        }
    }
}