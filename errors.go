package okta

import "errors"

var ErrWrongMFA = errors.New("no valid MFA configured")
var ErrLoginFailed = errors.New("login failed")
var ErrNoVerifyLink = errors.New("invalid token factor, no verify link found")
var ErrInvalidSAMLResp = errors.New("invalid SAML response")
var ErrDecodingSAMLB64 = errors.New("error decoding SAML base64")
var ErrDecodingSAMLXML = errors.New("error decoding SAML xml")
var ErrSessionCookieNotFound = errors.New("session cookie not found")
