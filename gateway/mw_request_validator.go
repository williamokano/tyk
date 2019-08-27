package gateway

import (
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"hash"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/headers"
	"github.com/TykTechnologies/tyk/regexp"
	"github.com/TykTechnologies/tyk/user"
)

const dateHeaderSpec = "Date"
const altHeaderSpec = "x-aux-date"

// SignatureVerficationMiddleware will check if the request has a signature, and if the request is allowed through
type SignatureVerficationMiddleware struct {
	BaseMiddleware
	lowercasePattern *regexp.Regexp
}

func (hm *SignatureVerficationMiddleware) Name() string {
	return "HMAC"
}

func (k *SignatureVerficationMiddleware) EnabledForSpec() bool {
	return k.Spec.EnableSignatureChecking
}

func (hm *SignatureVerficationMiddleware) Init() {
	hm.lowercasePattern = regexp.MustCompile(`%[a-f0-9][a-f0-9]`)
}

func (hm *SignatureVerficationMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	token := r.Header.Get("Authorization")
	if token == "" {
		return hm.authorizationError(r)
	}
	logger := hm.Logger().WithField("key", obfuscateKey(token))

	// Clean it
	token = stripSignature(token)

	// Separate out the field values
	fieldValues, err := getFieldValues(token)
	if err != nil {
		logger.WithError(err).Error("Field extraction failed")
		return hm.authorizationError(r)
	}

	// Generate a signature string
	signatureString, err := generateSignatureStringFromRequest(r, fieldValues.Headers)
	if err != nil {
		logger.WithError(err).WithField("signature_string", signatureString).Error("Signature string generation failed")
		return hm.authorizationError(r)
	}

	if len(hm.Spec.HmacAllowedAlgorithms) > 0 {
		algorithmAllowed := false
		for _, alg := range hm.Spec.HmacAllowedAlgorithms {
			if alg == fieldValues.Algorthm {
				algorithmAllowed = true
				break
			}
		}
		if !algorithmAllowed {
			logger.WithError(err).WithField("algorithm", fieldValues.Algorthm).Error("Algorithm not supported")
			return hm.authorizationError(r)
		}
	}

	var secret string
	var rsaKey *rsa.PublicKey
	var session user.SessionState

	if strings.HasPrefix(fieldValues.Algorthm, "rsa") {
		var certificateId string

		certificateId, session, err = hm.getRSACertificateIdAndSessionForKeyID(r, fieldValues.KeyID)
		if err != nil {
			logger.WithError(err).WithFields(logrus.Fields{
				"keyID": fieldValues.KeyID,
			}).Error("Failed to fetch session/public key")
			return hm.authorizationError(r)
		}

		publicKey := CertificateManager.ListRawPublicKey(certificateId)
		if publicKey == nil {
			log.Error("Certificate not found")
			return errors.New("Certificate not found"), http.StatusInternalServerError
		}
		var ok bool
		rsaKey, ok = publicKey.(*rsa.PublicKey)
		if !ok {
			log.Error("Certificate doesn't contain RSA Public key")
			return errors.New("Certificate doesn't contain RSA Public key"), http.StatusInternalServerError
		}
	} else {
		// Get a session for the Key ID
		secret, session, err = hm.getSecretAndSessionForKeyID(r, fieldValues.KeyID)
		if err != nil {
			logger.WithError(err).WithFields(logrus.Fields{
				"keyID": fieldValues.KeyID,
			}).Error("No HMAC secret for this key")
			return hm.authorizationError(r)
		}
	}
	var matchPass bool

	if strings.HasPrefix(fieldValues.Algorthm, "rsa") {
		matchPass, err = validateRSAEncodedSignature(signatureString, rsaKey, fieldValues.Algorthm, fieldValues.Signature)
		if err != nil {
			logger.WithError(err).Error("Signature validation failed.")
		}

		if !matchPass {
			isLower, lowerList := hm.hasLowerCaseEscaped(fieldValues.Signature)
			if isLower {
				logger.Debug("--- Detected lower case encoding! ---")
				upperedSignature := hm.replaceWithUpperCase(fieldValues.Signature, lowerList)
				matchPass, err = validateRSAEncodedSignature(signatureString, rsaKey, fieldValues.Algorthm, upperedSignature)
				if err != nil {
					logger.WithError(err).Error("Signature validation failed.")
				}
			}
		}

		if !matchPass {
			logger.WithFields(logrus.Fields{
				"got": fieldValues.Signature,
			}).Error("Signature string does not match!")
			return hm.authorizationError(r)
		}
	} else {
		// Create a signed string with the secret
		encodedSignature := generateHMACEncodedSignature(signatureString, secret, fieldValues.Algorthm)

		// Compare
		matchPass = encodedSignature == fieldValues.Signature

		// Check for lower case encoding (.Net issues, again)
		if !matchPass {
			isLower, lowerList := hm.hasLowerCaseEscaped(fieldValues.Signature)
			if isLower {
				logger.Debug("--- Detected lower case encoding! ---")
				upperedSignature := hm.replaceWithUpperCase(fieldValues.Signature, lowerList)
				if encodedSignature == upperedSignature {
					matchPass = true
					encodedSignature = upperedSignature
				}
			}
		}

		if !matchPass {
			logger.WithFields(logrus.Fields{
				"expected": encodedSignature,
				"got":      fieldValues.Signature,
			}).Error("Signature string does not match!")
			return hm.authorizationError(r)
		}
	}

	// Check clock skew
	_, dateVal := getDateHeader(r)
	if !hm.checkClockSkew(dateVal) {
		logger.Error("Clock skew outside of acceptable bounds")
		return hm.authorizationError(r)
	}

	// Set session state on context, we will need it later
	switch hm.Spec.BaseIdentityProvidedBy {
	case apidef.HMACKey, apidef.UnsetAuth:
		ctxSetSession(r, &session, fieldValues.KeyID, false)
		hm.setContextVars(r, fieldValues.KeyID)
	}

	// Everything seems in order let the request through
	return nil, http.StatusOK
}

func stripSignature(token string) string {
	token = strings.TrimPrefix(token, "Signature")
	token = strings.TrimPrefix(token, "signature")
	return strings.TrimSpace(token)
}

func (hm *SignatureVerficationMiddleware) hasLowerCaseEscaped(signature string) (bool, []string) {
	foundList := hm.lowercasePattern.FindAllString(signature, -1)
	return len(foundList) > 0, foundList
}

func (hm *SignatureVerficationMiddleware) replaceWithUpperCase(originalSignature string, lowercaseList []string) string {
	newSignature := originalSignature
	for _, lStr := range lowercaseList {
		asUpper := strings.ToUpper(lStr)
		newSignature = strings.Replace(newSignature, lStr, asUpper, -1)
	}

	return newSignature
}

func (hm *SignatureVerficationMiddleware) setContextVars(r *http.Request, token string) {
	if !hm.Spec.EnableContextVars {
		return
	}
	// Flatten claims and add to context
	if cnt := ctxGetData(r); cnt != nil {
		// Key data
		cnt["token"] = token
		ctxSetData(r, cnt)
	}
}

func (hm *SignatureVerficationMiddleware) authorizationError(r *http.Request) (error, int) {
	hm.Logger().Info("Authorization field missing or malformed")

	AuthFailed(hm, r, r.Header.Get(headers.Authorization))

	return errors.New("Authorization field missing, malformed or invalid"), http.StatusBadRequest
}

func (hm SignatureVerficationMiddleware) checkClockSkew(dateHeaderValue string) bool {
	// Reference layout for parsing time: "Mon Jan 2 15:04:05 MST 2006"
	refDate := "Mon, 02 Jan 2006 15:04:05 MST"
	// Fall back to a numeric timezone, since some environments don't provide a timezone name code
	refDateNumeric := "Mon, 02 Jan 2006 15:04:05 -07"

	tim, err := time.Parse(refDate, dateHeaderValue)
	if err != nil {
		tim, err = time.Parse(refDateNumeric, dateHeaderValue)
	}

	if err != nil {
		hm.Logger().WithError(err).WithField("date_string", tim).Error("Date parsing failed")
		return false
	}

	inSec := tim.UnixNano()
	now := time.Now().UnixNano()

	diff := now - inSec

	in_ms := diff / 1000000

	if hm.Spec.HmacAllowedClockSkew <= 0 {
		return true
	}

	if math.Abs(float64(in_ms)) > hm.Spec.HmacAllowedClockSkew {
		hm.Logger().Debug("Difference is: ", math.Abs(float64(in_ms)))
		return false
	}

	return true
}

type HMACFieldValues struct {
	KeyID     string
	Algorthm  string
	Headers   []string
	Signature string
}

func (hm *SignatureVerficationMiddleware) getSecretAndSessionForKeyID(r *http.Request, keyId string) (string, user.SessionState, error) {
	session, keyExists := hm.CheckSessionAndIdentityForValidKey(keyId, r)
	if !keyExists {
		return "", session, errors.New("Key ID does not exist")
	}

	if session.HmacSecret == "" || !session.HMACEnabled && !session.EnableHTTPSignatureValidation {
		hm.Logger().Info("API Requires HMAC signature, session missing HMACSecret or HMAC not enabled for key")

		return "", session, errors.New("This key ID is invalid")
	}

	return session.HmacSecret, session, nil
}

func (hm *SignatureVerficationMiddleware) getRSACertificateIdAndSessionForKeyID(r *http.Request, keyId string) (string, user.SessionState, error) {
	session, keyExists := hm.CheckSessionAndIdentityForValidKey(keyId, r)
	if !keyExists {
		return "", session, errors.New("Key ID does not exist")
	}

	if session.RSACertificateId == "" || !session.EnableHTTPSignatureValidation {
		hm.Logger().Info("API Requires RSA signature, session missing RSA Certificate Id or RSA not enabled for key")
		return "", session, errors.New("This key ID is invalid")
	}

	return session.RSACertificateId, session, nil
}

func getDateHeader(r *http.Request) (string, string) {
	auxHeaderVal := r.Header.Get(altHeaderSpec)
	// Prefer aux if present
	if auxHeaderVal != "" {
		token := r.Header.Get(headers.Authorization)
		log.WithFields(logrus.Fields{
			"prefix":      "hmac",
			"auth_header": token,
		}).Warning("Using auxiliary header for this request")
		return strings.ToLower(altHeaderSpec), auxHeaderVal
	}

	dateHeaderVal := r.Header.Get(dateHeaderSpec)
	if dateHeaderVal != "" {
		log.WithFields(logrus.Fields{
			"prefix": "hmac",
		}).Debug("Got date header")
		return strings.ToLower(dateHeaderSpec), dateHeaderVal
	}

	return "", ""
}

func getFieldValues(authHeader string) (*HMACFieldValues, error) {
	set := HMACFieldValues{}

	for _, element := range strings.Split(authHeader, ",") {
		kv := strings.SplitN(element, "=", 2)

		key := strings.ToLower(kv[0])
		value := strings.Trim(kv[1], `"`)

		switch key {
		case "keyid":
			set.KeyID = value
		case "algorithm":
			set.Algorthm = value
		case "headers":
			set.Headers = strings.Split(value, " ")
		case "signature":
			set.Signature = value
		default:
			log.WithFields(logrus.Fields{
				"prefix": "hmac",
				"field":  kv[0],
			}).Warning("Invalid header field found")
			return nil, errors.New("Header key is not valid, not in allowed parameter list")
		}
	}

	// Date is the absolute minimum header set
	if len(set.Headers) == 0 {
		set.Headers = append(set.Headers, "date")
	}

	return &set, nil
}

// "Signature keyId="9876",algorithm="hmac-sha1",headers="x-test x-test-2",signature="queryEscape(base64(sig))"")

func generateSignatureStringFromRequest(r *http.Request, headers []string) (string, error) {
	signatureString := ""
	for i, header := range headers {
		loweredHeader := strings.TrimSpace(strings.ToLower(header))
		if loweredHeader == "(request-target)" {
			requestHeaderField := "(request-target): " + strings.ToLower(r.Method) + " " + r.URL.Path
			signatureString += requestHeaderField
		} else {
			// exception for dates and .Net oddness
			headerVal := r.Header.Get(loweredHeader)
			if loweredHeader == "date" {
				loweredHeader, headerVal = getDateHeader(r)
			}
			headerField := strings.TrimSpace(loweredHeader) + ": " + strings.TrimSpace(headerVal)
			signatureString += headerField
		}

		if i != len(headers)-1 {
			signatureString += "\n"
		}
	}
	log.Debug("Generated sig string: ", signatureString)
	return signatureString, nil
}

func generateHMACEncodedSignature(signatureString, secret string, algorithm string) string {
	key := []byte(secret)

	var hashFunction func() hash.Hash

	switch algorithm {
	case "hmac-sha256":
		hashFunction = sha256.New
	case "hmac-sha384":
		hashFunction = sha512.New384
	case "hmac-sha512":
		hashFunction = sha512.New
	default:
		hashFunction = sha1.New
	}

	h := hmac.New(hashFunction, key)
	h.Write([]byte(signatureString))
	encodedString := base64.StdEncoding.EncodeToString(h.Sum(nil))
	return url.QueryEscape(encodedString)
}

func validateRSAEncodedSignature(signatureString string, publicKey *rsa.PublicKey, algorithm string, signature string) (bool, error) {
	var hashFunction hash.Hash
	var hashType crypto.Hash

	switch algorithm {
	case "rsa-sha256":
		hashFunction = sha256.New()
		hashType = crypto.SHA256
	default:
		hashFunction = sha256.New()
		hashType = crypto.SHA256
	}
	hashFunction.Write([]byte(signatureString))
	hashed := hashFunction.Sum(nil)

	decodedSignature, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		log.Error("Error while base64 decoding signature:", err)
		return false, err
	}
	err = rsa.VerifyPKCS1v15(publicKey, hashType, hashed, decodedSignature)
	if err != nil {
		log.Error("Signature match failed:", err)
		return false, err
	}

	return true, nil
}
