#!/usr/bin/env python
#
# This script checks if a github pull request was changed after approval, for
# example by a force-push or merge operation
# Method:
#    - Clone the repo to a temporary working directory.
#    - Merge the pull request into the target branch - the approved version and
#      the current version.
#    - Compare the merge result in both cases.
#
# Example usage:
#    $ ./contrib/pr_app_check.py --pr 7689
#    no differences found
#
from git import Repo # pip install gitutils
from optparse import OptionParser
import subprocess
import requests
import getpass
import shutil
import sys
import os

class PRChecker(object):
    def __init__(self):
        # Other fields are set by parse_args()
        self.temp_dir = None
        self.verbose = False

    def __del__(self):
        self.remove_temp_dir()

    def remove_temp_dir(self):
        if self.temp_dir and os.path.exists(self.temp_dir):
            if self.verbose:
                print("removing %s" % self.temp_dir)
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def github_api_call(self, req, page=1):
        """
        Call the github API with the given request.
        """
        url = "https://api.github.com/repos/%s/pulls/%s%s" % \
            (self.repo_path, self.pr_num, req)
        r = requests.get(url=url, params={"page": str(page)})
        data = r.json()
        if 'message' in data:
            # failure message from github api
            raise Exception("%s: %s" % (data['message'], url))
        return data

    def get_head_commit(self):
        """
        Set self.head_commit to the hash of the latest PR commit.
        """
        data = self.github_api_call(req="")
        self.target_branch = data[u'base'][u'ref']
        if not self.target_branch:
            raise Exception("No target branch found")
        pr_state = data[u'state']
        if pr_state != u'open':
            raise Exception("Pull request %s state is %s, expected: open" %
                            (self.pr_num, pr_state))
        self.head_commit = data[u'head'][u'sha']
        if not self.head_commit:
            raise Exception("No head commit found")
        if self.verbose:
            print("github head commit: %s" % self.head_commit[:7])

    def get_approved_commit(self):
        """
        Set self.approved_commit to the hash of the latest approved PR commit.
        """
        page = 1
        self.approved_commit = None
        while True:
            data = self.github_api_call(req="/reviews", page=page)
            if not data:
                break
            for d in data:
                if d[u'state'] == u'APPROVED' and \
                        d[u'user'][u'login'] == self.approving_user:
                    self.approved_commit = str(d[u'commit_id'])
            page += 1
        if not self.approved_commit:
            raise Exception("No approved commit by user '%s' found" %
                            self.approving_user)
        if self.verbose:
            print("github approved commit: %s (by '%s')" %
                  (self.approved_commit[:7], self.approving_user))

    def init_repo(self):
        """
        Initialize self.repo and self.branch_spec to the target branch.
        """
        self.remove_temp_dir()
        self.repo = Repo.init(self.temp_dir)
        if self.verbose:
            print("initialized empty repo at %s" % self.temp_dir)
        self.remote = self.repo.create_remote(
            self.remote_name, 'https://github.com/%s' % self.repo_path)
        self.remote.fetch(self.target_branch, depth=self.depth)
        self.branch_spec = '%s/%s' % (self.remote_name, self.target_branch)
        if self.verbose:
            print("fetched %s as %s" % (self.branch_spec,
                  self.repo.git.rev_parse(self.branch_spec)[:7]))

    def merge(self, commit):
        """
        Merge the given commit with self.branch_spec and return the hash of the
        resulting commit.
        """
        self.remote.fetch(commit, depth=self.depth)
        self.repo.git.checkout(commit)
        self.repo.git.merge(self.branch_spec, m='Merge %s' % commit)
        if self.verbose:
            print(" - merge of %s to %s is %s" %
                  (commit[:7], self.branch_spec, str(self.repo.head.commit)[:7]))
        return self.repo.head.commit

    def parse_args(self, argv):
        parser = OptionParser(usage="usage: %prog [options]")
        parser.add_option("--pr", action="store", dest="pr_num",
                          help="Pull request number to check")
        parser.add_option("--approve-by", action="store", dest="approve_by",
                          metavar="USER",
                          default = getpass.getuser(),
                          help="GitHub user name of approving user [default: %default]")
        parser.add_option("--temp-dir", action="store", dest="temp_dir",
                          metavar="PATH",
                          default="/tmp/%s" % getpass.getuser(),
                          help="Temporary work directory [default: %default]")
        parser.add_option("--repo", action="store", dest="repo",
                          metavar="ORG/REPO",
                          default="openucx/ucx",
                          help="GitHub repository path [default: %default]")
        parser.add_option("--depth", action="store", dest="depth",
                          default=50,
                          help="Fetch depth [default: %default]")
        parser.add_option("--remote", action="store", dest="remote",
                          default="upstream",
                          help="Remote name in the local repository [default: %default]")
        parser.add_option("-v", action="store_true", dest="verbose",
                          default=False,
                          help="Verbose output")
        (options, args) = parser.parse_args()
        if not options.pr_num:
            print("Error: Missing PR number")
            sys.exit(1)

        self.pr_num = options.pr_num
        self.approving_user = options.approve_by
        self.temp_dir = os.path.join(options.temp_dir, "pr_check")
        self.repo_path = options.repo
        self.depth = options.depth
        self.remote_name = options.remote
        self.verbose = options.verbose

    def print_diff(self, diff):
        if shutil.which("ydiff"):
            # ydiff colorizes the diff output. install with "pip install ydiff".
            # pass 'cat' as the pager to disable paging
            subprocess.run(["ydiff", "-p", "cat"],
                           input=str(diff + "\n").encode())
        else:
            print(diff)

    def main(self, argv):
        self.parse_args(argv)
        self.get_head_commit()
        self.get_approved_commit()
        self.init_repo()

        if self.verbose:
            print("comparing %s and %s when merged to %s" %
                  (self.approved_commit[:7], self.head_commit[:7], self.target_branch))

        merge_approved = self.merge(self.approved_commit)
        merge_head = self.merge(self.head_commit)

        diff = self.repo.git.diff(merge_approved, merge_head)
        if not diff:
            print("no differences found")
            return 0

        self.print_diff(diff)
        return 1


if __name__ == "__main__":
    checker = PRChecker()
    sys.exit(checker.main(sys.argv))
