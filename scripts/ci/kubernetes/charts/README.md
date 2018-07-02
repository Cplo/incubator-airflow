### airflow install

- DEV ENV  
helm --kube-context dev --namespace airflow install --name airflow ./  -f values-dev.yaml  
或者  
helm --kube-context dev install --name airflow ./ --namespace airflow --set gitsync.env.GIT_SYNC_BRANCH=dev

- PROD ENV  
helm --kube-context prod install --name airflow ./ --namespace airflow -f values-prod.yaml  
或者  
helm --kube-context prod install --name airflow ./ --namespace airflow --set gitsync.env.GIT_SYNC_BRANCH=prod