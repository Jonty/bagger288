import sys
import os

from github import Github
import bagger288

def get_org_repos(orgname):
    g = Github(login_or_token=os.environ['GITHUB_API_TOKEN'])
    for repo in g.get_organization(orgname).get_repos(type='private'):
        print
        print('\033[94m###############################################################################################################')
        print('searching ' + repo.html_url)
        print('###############################################################################################################\033[0m')
        bagger288.print_commits(bagger288.find_strings('git@github.com:%s/%s.git' % (orgname, repo.name)))

if __name__ == "__main__":
    print(">>> Excavating the %s github org" % sys.argv[1])
    get_org_repos(sys.argv[1])
