package main

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"io"
	"net/http"
	"os"
	"github.com/Workiva/hello-go-saml/saml"
)

const version = "0.0.1"

const SigninPage = `
<!DOCTYPE html>
<html lang="en" charset="utf-8">
<body>
<h1>You're not signed in</h1>
<a href="https://dev-580463.oktapreview.com/home/workivadev580463_deleteme_3/0oackxgy6t4laEyDm0h7/alnckxsy9rsU0H7fH0h7">Sign me in already!</a>
</body>
</html>
`

func RenderSignin(w http.ResponseWriter) {
	io.WriteString(w, SigninPage)
}

const HomePage = `
<!DOCTYPE html>
<html lang="en" charset="utf-8">
<body>
<h1>Hooray you're signed in</h1>'
</body>
</html>
`

func RenderHome(w http.ResponseWriter) {
	io.WriteString(w, HomePage)
}

func HandleRoot(w http.ResponseWriter, req *http.Request) {
	log.Info(fmt.Sprintf("Request %v", req))
	loggedIn := false

	if !loggedIn {
		RenderSignin(w)
		return
	}

	RenderHome(w)
}

const SsoPageStart = `
<!DOCTYPE html>
<html lang="en" charset="utf-8">
<body>
<h1>IDP stuff</h1>
`

const SsoPageEnd = `
</body>
</html>
`

func HandleIdp(w http.ResponseWriter, req *http.Request) {
	encodedXml := req.FormValue("SAMLResponse")
	buf, err := base64.StdEncoding.DecodeString(encodedXml)

	if err != nil {
		log.Warn("Bad saml response", err)
		http.Error(w, "Unauthorized", 401)
		return
	}

	log.Info("unmarshal xml")
	response := saml.Response{}
	err = xml.Unmarshal(buf, &response)

	if err != nil {
		log.Warn("Failed to unmarshal", err)
		http.Error(w, "Unauthorized", 401)
		return
	}


	log.Info("validating saml response")

	response.OriginalString = string(buf)

	serviceProviderSettings := saml.ServiceProviderSettings{
		PublicCertPath:              "/tmp/foo.txt",
		PrivateKeyPath:              "something",
		IdpPublicCertPath:           "/go/okta.cert",
		AssertionConsumerServiceUrl: "http://f4540b65.ngrok.io/saml/sso/eample-okta-com",
		IdpSsoDescriptorUrl:         "http://www.okta.com/exkckxgy6sHOM46AL0h7",
		IdpSsoUrl:                   "https://dev-580463.oktapreview.com/app/workivadev580463_deleteme_3/exkckxgy6sHOM46AL0h7/sso/saml",
		SpSignRequest:               true,
	}

	err = response.Authenticate(&serviceProviderSettings)

	if err != nil {
		log.Warn("SAML Response validation failed", err)
		http.Error(w, "Unauthorized", 401)
		return
	}

	samlId := response.GetAttribute("uid")

	if samlId == "" {
		log.Warn("SAML Response missing uid attribute!!!")
		http.Error(w, "Unauthorized", 401)
		return
	}

	log.Info("I guess this means everything is a-ok???")

	io.WriteString(w, SsoPageStart)
	io.WriteString(w, SsoPageEnd)
	// do a redirect????
}

func main() {
	port := os.Args[1]
	log.Info(fmt.Sprintf("hello-saml version %v listening on port %v", version, port))

	http.HandleFunc("/saml/sso/", HandleIdp)
	http.HandleFunc("/", HandleRoot)
	log.Fatal(http.ListenAndServe(":5555", nil))
}
