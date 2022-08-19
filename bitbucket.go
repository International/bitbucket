package bitbucket

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/International/bitbucket/diff"
	"github.com/pkg/errors"
	"golang.org/x/xerrors"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"time"
)

type queuedDownload struct {
	Name          string
	RelevantForPR bool
}

func DefaultHttpClient() *http.Client {
	cli := &http.Client{Timeout: 30 * time.Second}
	return cli
}

type PullRequestDescription struct {
	FromBranch string
	Commit     string
	ToBranch   string
}

type pullRequestBranch struct {
	Name string
}

type pullRequestCommit struct {
	Hash string
}

type pullRequestSource struct {
	Branch pullRequestBranch
	Commit pullRequestCommit
}

type pullRequestDetails struct {
	Source      pullRequestSource
	Destination pullRequestSource
}

type Logger interface {
	Println(args ...interface{}) error
}

type BitBucketClient struct {
	RepoOwner string
	Repo      string
	UserName  string
	Password  string
	client    *http.Client
	baseUrl   string
	Logger    *log.Logger
}

func NewClient(repoOwner, repo, userName, password string) *BitBucketClient {

	httpCli := DefaultHttpClient()

	return &BitBucketClient{
		RepoOwner: repoOwner, Repo: repo,
		UserName: userName, Password: password,
		client: httpCli, baseUrl: "https://api.bitbucket.org/2.0",
	}
}

func (b *BitBucketClient) formURL(relative string) string {
	return fmt.Sprintf("%s/%s", b.baseUrl, relative)
}

type Comment struct {
	File string
	Text string
	Line diff.LineNumber
}

func ParseRepoInfo(pullRequestURL string) (string, string, string, error) {
	re := regexp.MustCompile(`bitbucket.org/([^/]+)/([^/]+)/pull-requests/(\d+)/`)
	matches := re.FindAllStringSubmatch(pullRequestURL, -1)
	if len(matches) != 1 {
		return "", "", "", errors.New(fmt.Sprintf("failed to parse pullRequestURL %s", pullRequestURL))
	}
	extractedGroups := matches[0]
	if len(extractedGroups) != 4 {
		return "", "", "", errors.New(fmt.Sprintf("unexpected matches extracted: %+v", extractedGroups))
	}
	return extractedGroups[1], extractedGroups[2], extractedGroups[3], nil
}

func (b *BitBucketClient) PostComment(pullRequestId string, comment Comment) ([]byte, error) {
	placeholderURL := b.formURL("repositories/%s/%s/pullrequests/%s/comments")
	url := fmt.Sprintf(placeholderURL, b.RepoOwner, b.Repo, pullRequestId)
	bade := map[string]interface{}{
		"content": map[string]string{
			"raw": comment.Text,
		},
		"inline": map[string]interface{}{
			"to":   comment.Line,
			"path": comment.File,
		},
	}
	encoded, err := json.MarshalIndent(bade, "", "  ")
	if err != nil {
		return nil, errors.Wrap(err, "could not serialize comment body")
	}
	if os.Getenv("DEBUG") != "" {
		fmt.Println("posting|", string(encoded), "|")
	}
	contentType := "application/json"
	authenticatedReq, err := b.prepareAuthenticatedRequest("POST", url, contentType, bytes.NewReader(encoded))
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("could not prepare authenticated request to: %s", url))
	}
	response, err := b.client.Do(authenticatedReq)
	defer response.Body.Close()

	if err != nil {
		return nil, errors.Wrap(err, "could not post comment")
	}

	contents, err := ioutil.ReadAll(response.Body)

	if response.StatusCode != 201 {
		return nil, errors.New(fmt.Sprintf("expected status code of 201 when posting comment, got:%s", string(contents)))
	}

	return contents, err
}

func (b *BitBucketClient) prepareAuthenticatedRequest(method, url string, contentType string, body io.Reader) (*http.Request, error) {
	request, err := http.NewRequest(method, url, body)

	if err != nil {
		return nil, errors.Wrap(err, "failed to instantiate request")
	}

	credentials := fmt.Sprintf("%s:%s", b.UserName, b.Password)
	credentials = base64.StdEncoding.EncodeToString([]byte(credentials))

	request.Header.Set("Authorization", fmt.Sprintf("Basic %s", credentials))
	request.Header.Set("Accept", "application/json")

	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}

	return request, nil
}

func (b *BitBucketClient) DeleteCodeReviewRequestChanges(pullRequestId string) error {
	partialUrl := fmt.Sprintf("repositories/%s/%s/pullrequests/%s/request-changes", b.RepoOwner, b.Repo, pullRequestId)
	reqUrl := b.formURL(partialUrl)
	request, err := b.prepareAuthenticatedRequest("DELETE", reqUrl, "", nil)
	if err != nil {
		return errors.Wrap(err, "failed to create request")
	}
	resp, err := b.client.Do(request)
	if err != nil {
		return errors.Wrap(err, "failed to perform request")
	}
	if resp.StatusCode != 204 {
		actBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return errors.Wrap(err, "failed to parse error body")
		}
		resp.Body.Close()
		return fmt.Errorf("unexpected status code:%d issue:%s", resp.StatusCode, string(actBody))
	}
	return nil
}

func (b *BitBucketClient) CommitDiff(spec, target string) ([]byte, error) {
	diffURL := b.formURL(fmt.Sprintf("repositories/%s/%s/diff/%s..%s", b.RepoOwner, b.Repo, spec, target))
	response, err := b.performGet(diffURL)

	if err != nil {
		return nil, xerrors.Errorf("CommitDiff: %w", err)
	}

	return response, nil
}

func (b *BitBucketClient) MultipleFilesFromBranch(branch string, files []queuedDownload) (map[queuedDownload][]byte, error) {
	fileContents := map[queuedDownload][]byte{}
	for _, file := range files {
		log.Println("obtaining source of file", file.Name)
		contents, err := b.FileFromBranch(branch, file.Name)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("failed to obtain file:%s from SHA:%s", file.Name, branch))
		}
		time.Sleep(500 * time.Millisecond)
		fileContents[file] = contents
	}

	return fileContents, nil
}

func (b *BitBucketClient) FileFromBranch(branch, file string) ([]byte, error) {
	placeholderURL := b.formURL("repositories/%s/%s/src/%s/%s")
	actualURL := fmt.Sprintf(placeholderURL, b.RepoOwner, b.Repo, branch, file)
	body, err := b.performGet(actualURL)

	if err != nil {
		return nil, err
	}

	return body, nil
}

func (b *BitBucketClient) PullRequestInfo(pullRequestId string) (PullRequestDescription, error) {
	var desc PullRequestDescription
	placeholderURL := b.formURL("repositories/%s/%s/pullrequests/%s")
	pullRequestDiffUrl := fmt.Sprintf(placeholderURL, b.RepoOwner, b.Repo, pullRequestId)

	body, err := b.performGet(pullRequestDiffUrl)

	if err != nil {
		return desc, err
	}

	if os.Getenv("DEBUG") != "" {
		fmt.Println("got back:|", string(body), "|")
	}
	var details pullRequestDetails
	err = json.Unmarshal(body, &details)
	if err != nil {
		return desc, err
	}

	desc.FromBranch = details.Source.Branch.Name
	desc.ToBranch = details.Destination.Branch.Name
	desc.Commit = details.Source.Commit.Hash

	return desc, nil
}

func (b *BitBucketClient) performGet(url string) ([]byte, error) {

	request, err := b.prepareAuthenticatedRequest("GET", url, "", nil)

	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("could not prepare an authenticated request to %s", url))
	}

	response, err := b.client.Do(request)
	defer response.Body.Close()

	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("failed to request %s", url))
	}

	contents, err := ioutil.ReadAll(response.Body)

	if response.StatusCode != 200 {
		return nil, errors.New(
			fmt.Sprintf("server responded with:%s, status:%d", string(contents), response.StatusCode))
	}

	return contents, err
}

func (b *BitBucketClient) PullRequestDiff(pullRequestId string) ([]diff.ModifiedFile, error) {
	placeholderURL := b.formURL("repositories/%s/%s/pullrequests/%s/diff")
	pullRequestDiffUrl := fmt.Sprintf(placeholderURL, b.RepoOwner, b.Repo, pullRequestId)

	contents, err := b.performGet(pullRequestDiffUrl)
	if err != nil {
		return nil, err
	}

	modifiedFiles, err := diff.ReadDiff(bytes.NewReader(contents))
	if err != nil {
		return nil, errors.Wrap(err, "could not parse diff")
	}
	return modifiedFiles, nil
}
