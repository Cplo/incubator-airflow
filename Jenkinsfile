node('k8s-jenkins-slave-docker') {
    def appName = 'airflow'
    def orgName = 'devops'
    def scmVars = ''

    stage('checkout') {
        scmVars = checkout scm
    }

    stage('build') {
        sh '''
           python setup.py sdist -q
           cp dist/*.tar.gz scripts/ci/kubernetes/docker/airflow.tar.gz
        '''
    }

    stage('push docker') {
        
        def imageTag = ''
        def dagBranch = ''
        def dagsDir = "Airflow-DAGs/${orgName}/${appName}"
        gitlabBranch = gitlabBranch.replaceAll('/', '-').replaceAll('_', '-')
        if (gitlabBranch.startsWith("refs-tags-")) {
             // 如果提交tag则镜像tag则为tag名字
            imageTag = gitlabBranch.substring(10)
            dagBranch = 'prod'
        } else {
            // 以分支名+8位commit ID组成镜像tag
            imageTag = gitlabBranch + '-' + scmVars.GIT_COMMIT.substring(0, 8)
            dagBranch = 'dev'
        }

        dir ('scripts/ci/kubernetes/docker') {
            withDockerRegistry([credentialsId: 'jenkins-docker-reg', url: "https://docker-reg.devops.xiaohongshu.com/"]) {
                def image = docker.build("docker-reg.devops.xiaohongshu.com/${orgName}/${appName}:${imageTag}", "--pull --force-rm .")
                image.push()
            }
        }
        dir ('Airflow-DAGs') {
            git url: 'https://code.devops.xiaohongshu.com/pengchen/Airflow-DAGs.git', branch: "${dagBranch}"
        }
        sh "mkdir -p ${dagsDir}"
        sh "cp -fr airflow-dags/* ${dagsDir}"
        sh "sed \"s/IMAGETAG/${imageTag}/g\" -i ${dagsDir}/*.py"
        dir ('Airflow-DAGs') {
            sh "git add ."
            sh "git config --global user.email 'pengchen.xiaohongshu.com'"
            sh "git config --global user.name 'pengchen'"
            sh "git commit -m \"modify ${dagsDir}\""
            sh "git push https://pengchen:283049lo@code.devops.xiaohongshu.com/pengchen/Airflow-DAGs.git ${dagBranch}"
        }
    }
}
