package okta

import "encoding/xml"

type OktaLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Options  map[string]interface{}
}

type OktaLoginResponse struct {
	ExpiresAt    string
	SessionToken string
	Status       string
	StateToken   string
	Embedded     struct {
		Factors []OktaMFAFactor
	} `json:"_embedded"`
}

type OktaMFAFactor struct {
	Id         string
	FactorType string
	Provider   string
	Status     string
	Links      map[string]HalLink `json:"_links"`
}

type OktaSamlResponse struct {
	raw        string
	XMLname    xml.Name `xml:"Response"`
	Attributes []struct {
		Name  string   `xml:",attr"`
		Value []string `xml:"AttributeValue"`
	} `xml:"Assertion>AttributeStatement>Attribute"`
}

type HalLink struct {
	Href string
}
