package okta

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
)

func newLoginRequest(user, pass string) *OktaLoginRequest {
	return &OktaLoginRequest{
		user,
		pass,
		map[string]interface{}{
			"multiOptionalFactorEnroll": false,
			"warnBeforePasswordExpired": false,
		},
	}
}

func Login(ctx context.Context, cfg *OktaTile, user, pass string) (*OktaLoginResponse, error) {
	// POST /api/v1/authn
	u, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, err
	}

	u, err = u.Parse("/api/v1/authn")
	if err != nil {
		return nil, err
	}

	reqBody, err := encodeBody(newLoginRequest(user, pass))
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, u.String(), reqBody)
	if err != nil {
		return nil, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, ErrLoginFailed
	}

	defer func(r *http.Response) {
		_ = r.Body.Close()
	}(res)

	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var oRes OktaLoginResponse
	err = json.Unmarshal(b, &oRes)
	if err != nil {
		return nil, err
	}

	return &oRes, nil
}

func DoMFA(ctx context.Context, oRes *OktaLoginResponse, factor *OktaMFAFactor, token string) (*OktaLoginResponse, error) {
	verify, ok := factor.Links["verify"]
	if !ok {
		return nil, ErrNoVerifyLink
	}

	type body struct {
		StateToken string `json:"stateToken"`
		PassCode   string `json:"passCode"`
	}

	reqBody, err := encodeBody(body{oRes.StateToken, token})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, verify.Href, reqBody)
	if err != nil {
		return nil, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func(r *http.Response) {
		_ = r.Body.Close()
	}(res)

	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var mfaRes OktaLoginResponse
	err = json.Unmarshal(b, &mfaRes)
	if err != nil {
		return nil, err
	}

	if mfaRes.Status != "SUCCESS" {
		return nil, ErrLoginFailed
	}

	return &mfaRes, nil
}

func encodeBody(t interface{}) (io.Reader, error) {
	var b bytes.Buffer
	err := json.NewEncoder(&b).Encode(t)
	if err != nil {
		return nil, err
	}
	return &b, nil
}

func ExtractTokenFactor(oRes *OktaLoginResponse) (*OktaMFAFactor, error) {
	var tokenFactor OktaMFAFactor
	for _, factor := range oRes.Embedded.Factors {
		if factor.FactorType == "token:software:totp" {
			tokenFactor = factor
			break
		}
	}

	if tokenFactor.Id == "" {
		return nil, ErrWrongMFA
	}

	return &tokenFactor, nil
}
