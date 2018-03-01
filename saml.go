package okta

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"net/http"
	"net/http/cookiejar"
	"net/url"

	"github.com/PuerkitoBio/goquery"
)

func GetSAML(ctx context.Context, cfg *OktaTile, token string) (*OktaSamlResponse, *http.Cookie, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, nil, err
	}

	client := &http.Client{
		Jar:           jar,
		CheckRedirect: nil,
	}

	u, err := url.Parse(cfg.AppURL)
	if err != nil {
		return nil, nil, err
	}

	q := u.Query()
	q.Set("onetimetoken", token)
	u.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, nil, err
	}

	req = req.WithContext(ctx)

	res, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func(r *http.Response) {
		_ = r.Body.Close()
	}(res)

	saml, err := extractSamlResponse(res)
	if err != nil {
		return nil, nil, err
	}

	cookie, err := extractCookie(res)
	if err != nil {
		return nil, nil, err
	}

	return saml, cookie, nil

}

func extractSamlResponse(res *http.Response) (*OktaSamlResponse, error) {
	var osResp OktaSamlResponse

	doc, err := goquery.NewDocumentFromResponse(res)
	if err != nil {
		return nil, err
	}

	sel := doc.Find(`input[name="SAMLResponse"]`)
	if sel.Length() < 1 {
		return nil, ErrInvalidSAMLResp
	}

	saml, ok := sel.First().Attr("value")
	if !ok {
		return nil, ErrInvalidSAMLResp
	}

	osResp.raw = saml
	b, err := base64.StdEncoding.DecodeString(osResp.raw)
	if err != nil {
		return nil, ErrDecodingSAMLB64
	}

	err = xml.Unmarshal(b, &osResp)
	if err != nil {
		return nil, ErrDecodingSAMLXML
	}

	return &osResp, nil
}

func extractCookie(res *http.Response) (*http.Cookie, error) {
	for _, cookie := range res.Cookies() {
		if cookie.Name == "sid" {
			return cookie, nil
		}
	}
	return nil, ErrSessionCookieNotFound
}
