package saml

import "encoding/xml"

type Issuer struct {
	XMLName xml.Name
	SAML    string `xml:"xmlns:saml,attr"`
	Url     string `xml:",innerxml"`
}

type Algorithm struct {
	XMLName   xml.Name
	Algorithm string `xml:"Algorithm,attr"`
}

type Transforms struct {
	XMLName   xml.Name
	Transform []Algorithm
}

type DigestValue struct {
	XMLName xml.Name
}

type Reference struct {
	XMLName      xml.Name
	URI          string      `xml:"URI,attr"`
	Transforms   Transforms  `xml:",innerxml"`
	DigestMethod Algorithm   `xml:",innerxml"`
	DigestValue  DigestValue `xml:",innerxml"`
}

type SignedInfo struct {
	XMLName                xml.Name
	CanonicalizationMethod Algorithm
	SignatureMethod        Algorithm
	Reference              Reference
}

type SignatureValue struct {
	XMLName xml.Name
	Value   string `xml:",innerxml"`
}

type X509Certificate struct {
	XMLName xml.Name
	Cert    string `xml:",innerxml"`
}

type X509Data struct {
	XMLName         xml.Name
	X509Certificate X509Certificate `xml:",innerxml"`
}

type KeyInfo struct {
	XMLName  xml.Name
	X509Data X509Data `xml:",innerxml"`
}

type Signature struct {
	XMLName        xml.Name
	Id             string `xml:"Id,attr"`
	SignedInfo     SignedInfo
	SignatureValue SignatureValue
	KeyInfo        KeyInfo
}

type StatusCode struct {
	XMLName xml.Name
	Value   string `xml:",attr"`
}

type Status struct {
	XMLName    xml.Name
	StatusCode StatusCode `xml:"StatusCode"`
}

type NameID struct {
	XMLName         xml.Name
	Format          string `xml:",attr"`
	SPNameQualifier string `xml:",attr,omitempty"`
	Value           string `xml:",innerxml"`
}

type SubjectConfirmationData struct {
	XMLName      xml.Name
	InResponseTo string `xml:",attr"`
	NotOnOrAfter string `xml:",attr"`
	Recipient    string `xml:",attr"`
}

type SubjectConfirmation struct {
	XMLName                 xml.Name
	Method                  string `xml:",attr"`
	SubjectConfirmationData SubjectConfirmationData
}

type Subject struct {
	XMLName             xml.Name
	NameID              NameID
	SubjectConfirmation SubjectConfirmation
}

type Audience struct {
	XMLName xml.Name
	Value   string `xml:",innerxml"`
}

type AudienceRestriction struct {
	XMLName   xml.Name
	Audiences []Audience
}

type Conditions struct {
	XMLName              xml.Name
	NotBefore            string                `xml:",attr"`
	NotOnOrAfter         string                `xml:",attr"`
	AduienceRestrictions []AudienceRestriction `xml:"AudienceRestriction,omitempty"`
}

type AttributeValue struct {
	XMLName xml.Name
	Type    string `xml:"xsi:type,attr"`
	Value   string `xml:",innerxml"`
}

type Attribute struct {
	XMLName         xml.Name
	Name            string           `xml:",attr"`
	FriendlyName    string           `xml:",attr,omitempty"`
	NameFormat      string           `xml:",attr"`
	AttributeValues []AttributeValue `xml:"AttributeValue"`
}

type AuthnContextClassRef struct {
	XMLName   xml.Name
	SAML      string `xml:"xmlns:saml,attr"`
	Transport string `xml:",innerxml"`
}

type AuthnContext struct {
	XMLName              xml.Name
	AuthnContextClassRef AuthnContextClassRef `xml:"AuthnContextClassRef"`
}

type AuthnStatement struct {
	XMLName             xml.Name
	AuthnInstant        string       `xml:",attr"`
	SessionNotOnOrAfter string       `xml:",attr,omitempty"`
	SessionIndex        string       `xml:",attr,omitempty"`
	AuthnContext        AuthnContext `xml:"AuthnContext"`
}

type AttributeStatement struct {
	XMLName    xml.Name
	Attributes []Attribute `xml:"Attribute"`
}

type Assertion struct {
	XMLName            xml.Name
	ID                 string `xml:"ID,attr"`
	Version            string `xml:"Version,attr"`
	XS                 string `xml:"xmlns:xs,attr"`
	XSI                string `xml:"xmlns:xsi,attr"`
	SAML               string `xml:"xmlns:saml,attr"`
	IssueInstant       string `xml:"IssueInstant,attr"`
	Issuer             Issuer `xml:"Issuer"`
	Signature      Signature `xml:"Signature"`
	Subject            Subject
	Conditions         Conditions
	AuthnStatements    []AuthnStatement `xml:"AuthnStatement,omitempty"`
	AttributeStatement AttributeStatement
}

type Response struct {
	XMLName        xml.Name
	SAMLP          string    `xml:"xmlns:samlp,attr"`
	SAML           string    `xml:"xmlns:saml,attr"`
	SAMSIG         string    `xml:"xmlns:samlsig,attr"`
	Destination    string    `xml:"Destination,attr"`
	ID             string    `xml:"ID,attr"`
	Version        string    `xml:"Version,attr"`
	IssueInstant   string    `xml:"IssueInstant,attr"`
	InResponseTo   string    `xml:"InResponseTo,attr"`
	Issuer         Issuer    `xml:"Issuer"`
	//Signature      Signature `xml:"Signature"`
	Status         Status    `xml:"Status"`
	Assertion      Assertion `xml:"Assertion"`
	OriginalString string
}


type ServiceProviderSettings struct {
	PublicCertPath              string
	PrivateKeyPath              string
	IdpSsoUrl                   string
	IdpSsoDescriptorUrl         string
	IdpPublicCertPath           string
	AssertionConsumerServiceUrl string
	SpSignRequest               bool

	hasInit       bool
	publicCert    string
	privateKey    string
	idpPublicCert string
}

func (r *Response) GetAttribute(name string) string {
	for _, attr := range r.Assertion.AttributeStatement.Attributes {
		if attr.Name == name || attr.FriendlyName == name {
			return attr.AttributeValues[0].Value
		}
	}
	return ""
}