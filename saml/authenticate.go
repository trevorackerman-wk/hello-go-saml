package saml

import (
	"errors"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"time"
)

const xmlResponseID = "urn:oasis:names:tc:SAML:2.0:protocol:Response"

func verify(xml string, publicCertPath string, id string) error {
	samlXmlSecInput, err := ioutil.TempFile(os.TempDir(), "hello-saml")
	if err != nil {
		return err
	}

	samlXmlSecInput.WriteString(xml)
	samlXmlSecInput.Close()

	defer os.Remove(samlXmlSecInput.Name())

	x := []string{
		"xmlsec1", "--verify", "--pubkey-cert-pem", publicCertPath, "--id-attr:ID", id,
		samlXmlSecInput.Name(),
	}
	log.Info(strings.Join(x, " "))

	stdoutStderr, err := exec.Command("xmlsec1", "--verify", "--print-debug", "--pubkey-cert-pem", publicCertPath, "--id-attr:ID", id,
		samlXmlSecInput.Name()).CombinedOutput()

	fmt.Printf("%v\n", string(stdoutStderr))



	if err != nil {
		return errors.New("Error verifying signature: " + err.Error())
	}

	return nil
}

func VerifyResponseSignature(xml string, publicCertPath string) error {
	return verify(xml, publicCertPath, xmlResponseID)
}

func (r *Response) Authenticate(s *ServiceProviderSettings) error {

	log.Info("Authenticating response")
	if r.Version != "2.0" {
		return errors.New("unsupported SAML Version")
	}

	if len(r.ID) == 0 {
		return errors.New("missing ID attribute on SAML Response")
	}

	if len(r.Assertion.ID) == 0 {
		return errors.New("no assertions")
	}

	log.Info("Signature Value ", r.Assertion.Signature.SignatureValue.Value)

	if len(r.Assertion.Signature.SignatureValue.Value) == 0 {
		return errors.New("No Signature")
	}

	if r.Destination != s.AssertionConsumerServiceUrl {
		return errors.New(fmt.Sprintf("destination mismatch, expected: %v, actual: %v", s.AssertionConsumerServiceUrl, r.Destination))
	}

	if r.Assertion.Subject.SubjectConfirmation.Method != "urn:oasis:names:tc:SAML:2.0:cm:bearer" {
		return errors.New("Bad Assertion subject confirmation method " + r.Assertion.Subject.SubjectConfirmation.Method)
	}

	if r.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient != s.AssertionConsumerServiceUrl {
		return errors.New(fmt.Sprintf("subject recipient mismatch, expected: %v, actual %v", s.AssertionConsumerServiceUrl,
			r.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient))
	}

	err := VerifyResponseSignature(r.OriginalString, s.IdpPublicCertPath)

	if err != nil {
		return err
	}

	expires := r.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.NotOnOrAfter
	notOnOrAfter, err := time.Parse(time.RFC3339, expires)

	if err != nil {
		return err
	}

	if notOnOrAfter.Before(time.Now()) {
		return errors.New("assertion expired on: " + expires)
	}

	return nil
}
