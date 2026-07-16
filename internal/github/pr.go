package github

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/abdma/fixiac/internal/remediation"
	gh "github.com/google/go-github/v60/github"
	"golang.org/x/oauth2"
)

// PRCreator creates pull requests on GitHub using the REST API.
type PRCreator struct {
	client *gh.Client
	owner  string
	repo   string
}

// NewPRCreator initializes a new GitHub pull request creator.
func NewPRCreator(token, owner, repo string) *PRCreator {
	var client *gh.Client
	if token != "" {
		ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
		tc := oauth2.NewClient(context.Background(), ts)
		client = gh.NewClient(tc)
	} else {
		client = gh.NewClient(nil)
	}

	return &PRCreator{
		client: client,
		owner:  owner,
		repo:   repo,
	}
}

// CreatePR creates a pull request on GitHub.
func (p *PRCreator) CreatePR(ctx context.Context, branch, title, body string) (*gh.PullRequest, error) {
	if p.client == nil {
		return nil, fmt.Errorf("GitHub client not initialized (missing token)")
	}

	// Default base branch is main or master
	base := "main"
	newPR := &gh.NewPullRequest{
		Title:               gh.String(title),
		Head:                gh.String(branch),
		Base:                gh.String(base),
		Body:                gh.String(body),
		MaintainerCanModify: gh.Bool(true),
	}

	pr, _, err := p.client.PullRequests.Create(ctx, p.owner, p.repo, newPR)
	if err != nil && strings.Contains(err.Error(), "main") {
		// Try falling back to master if main base branch failed
		base = "master"
		newPR.Base = gh.String(base)
		pr, _, err = p.client.PullRequests.Create(ctx, p.owner, p.repo, newPR)
	}
	if err != nil {
		return nil, fmt.Errorf("creating pull request: %w", err)
	}

	// Try adding standard security labels
	labels := []string{"security", "automated", "fixiac"}
	_, _, labelErr := p.client.Issues.AddLabelsToIssue(ctx, p.owner, p.repo, pr.GetNumber(), labels)
	if labelErr != nil {
		// Non-fatal if labeling fails (user might not have label perms or labels don't exist)
		_ = labelErr
	}

	return pr, nil
}

// ParseRemote parses a git remote URL to extract owner and repo names.
func (p *PRCreator) ParseRemote(remoteName string) (owner, repo string, err error) {
	if remoteName == "" {
		remoteName = "origin"
	}
	out, err := exec.Command("git", "remote", "get-url", remoteName).Output()
	if err != nil {
		return "", "", fmt.Errorf("getting git remote %s: %w", remoteName, err)
	}

	url := strings.TrimSpace(string(out))
	url = strings.TrimSuffix(url, ".git")

	// SSH URL: git@github.com:owner/repo or https://github.com/owner/repo
	if strings.HasPrefix(url, "git@") {
		parts := strings.SplitN(url, ":", 2)
		if len(parts) == 2 {
			repoParts := strings.SplitN(parts[1], "/", 2)
			if len(repoParts) == 2 {
				return repoParts[0], repoParts[1], nil
			}
		}
	} else if strings.Contains(url, "github.com/") {
		parts := strings.SplitAfter(url, "github.com/")
		if len(parts) == 2 {
			repoParts := strings.SplitN(parts[1], "/", 2)
			if len(repoParts) == 2 {
				return repoParts[0], repoParts[1], nil
			}
		}
	}

	return "", "", fmt.Errorf("unable to parse GitHub owner/repo from remote URL: %s", url)
}

// CreateFixPR creates a new git branch, commits applied fixes, pushes the branch,
// and opens a GitHub Pull Request with the remediations.
func (p *PRCreator) CreateFixPR(ctx context.Context, targetDir string, fixes []*remediation.Fix) error {
	if len(fixes) == 0 {
		return nil
	}

	branchName := fmt.Sprintf("fixiac/remediate-%s", time.Now().UTC().Format("20060102-150405"))

	// Step 1: Checkout new branch
	cmdBranch := exec.Command("git", "checkout", "-b", branchName)
	cmdBranch.Dir = targetDir
	if out, err := cmdBranch.CombinedOutput(); err != nil {
		return fmt.Errorf("git checkout branch failed: %v (%s)", err, string(out))
	}

	// Step 2: Git add
	cmdAdd := exec.Command("git", "add", "-u")
	cmdAdd.Dir = targetDir
	if out, err := cmdAdd.CombinedOutput(); err != nil {
		return fmt.Errorf("git add failed: %v (%s)", err, string(out))
	}

	// Step 3: Git commit
	commitMsg := fmt.Sprintf("fix(security): apply %d automated IaC security remediations from fixiac", len(fixes))
	cmdCommit := exec.Command("git", "commit", "-m", commitMsg)
	cmdCommit.Dir = targetDir
	if out, err := cmdCommit.CombinedOutput(); err != nil {
		return fmt.Errorf("git commit failed: %v (%s)", err, string(out))
	}

	// Step 4: Git push
	cmdPush := exec.Command("git", "push", "-u", "origin", branchName)
	cmdPush.Dir = targetDir
	if out, err := cmdPush.CombinedOutput(); err != nil {
		return fmt.Errorf("git push failed: %v (%s)", err, string(out))
	}

	// Step 5: Build PR body
	var sb strings.Builder
	sb.WriteString("## 🔒 fixiac Automated Security Remediations\n\n")
	sb.WriteString(fmt.Sprintf("This Pull Request applies **%d** automated security fixes generated and validated by [`fixiac`](https://github.com/abdma/fixiac).\n\n", len(fixes)))
	sb.WriteString("### 🔍 Remediated Findings\n\n")
	for i, fix := range fixes {
		if fix == nil {
			continue
		}
		sb.WriteString(fmt.Sprintf("%d. **%s** (`%s`): %s\n", i+1, fix.Finding.RuleID, fix.Finding.Resource, fix.Explanation))
	}
	sb.WriteString("\n---\n*Generated by fixiac CLI*")

	// Step 6: Create PR via API
	_, err := p.CreatePR(ctx, branchName, commitMsg, sb.String())
	return err
}
