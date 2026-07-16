package github

import (
	"context"
	"fmt"

	gh "github.com/google/go-github/v60/github"
	"golang.org/x/oauth2"
)

// Commenter posts issue comments and review comments on GitHub pull requests.
type Commenter struct {
	client *gh.Client
	owner  string
	repo   string
}

// NewCommenter initializes a new GitHub commenter.
func NewCommenter(token, owner, repo string) *Commenter {
	var client *gh.Client
	if token != "" {
		ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
		tc := oauth2.NewClient(context.Background(), ts)
		client = gh.NewClient(tc)
	} else {
		client = gh.NewClient(nil)
	}

	return &Commenter{
		client: client,
		owner:  owner,
		repo:   repo,
	}
}

// PostComment posts a standard comment on a pull request.
func (c *Commenter) PostComment(ctx context.Context, prNumber int, body string) error {
	if c.client == nil {
		return fmt.Errorf("GitHub client not initialized (missing token)")
	}

	comment := &gh.IssueComment{
		Body: gh.String(body),
	}
	_, _, err := c.client.Issues.CreateComment(ctx, c.owner, c.repo, prNumber, comment)
	if err != nil {
		return fmt.Errorf("posting PR comment: %w", err)
	}
	return nil
}

// PostReviewComment posts a line-specific review comment on a pull request diff.
func (c *Commenter) PostReviewComment(ctx context.Context, prNumber int, file string, line int, body string) error {
	if c.client == nil {
		return fmt.Errorf("GitHub client not initialized (missing token)")
	}

	// Fetch PR details to get head commit SHA
	pr, _, err := c.client.PullRequests.Get(ctx, c.owner, c.repo, prNumber)
	if err != nil {
		return fmt.Errorf("getting PR #%d details: %w", prNumber, err)
	}

	comment := &gh.PullRequestComment{
		Body:     gh.String(body),
		CommitID: pr.GetHead().SHA,
		Path:     gh.String(file),
		Line:     gh.Int(line),
		Side:     gh.String("RIGHT"),
	}

	_, _, err = c.client.PullRequests.CreateComment(ctx, c.owner, c.repo, prNumber, comment)
	if err != nil {
		return fmt.Errorf("posting PR review comment: %w", err)
	}
	return nil
}
