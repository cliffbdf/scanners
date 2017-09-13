/*******************************************************************************
 * Implementation of ScanProvider for the Twistlock container scanner.
 * See:
 *	https://twistlock.desk.com/customer/en/portal/topics/876139-twistlock-api/articles
 *	https://twistlock.desk.com/customer/en/portal/articles/2831956-twistlock-api-2-1
 *		(See "Selective Repository Scan")
 *	Check ability to access the API:
 *		curl -k -u admin:admin https://localhost:8083/api/v1/defenders
 *	Configuring registry scanning:
 *		https://twistlock.desk.com/customer/portal/articles/2309759-configure-registry-scans
 *	Performing a scan:
 *		curl -k -u admin:admin -H "Content-Type: application/json" -d '{"tag":{"registry":"","repo":"scaledmarkets/taskruntime"}}' -X POST http://localhost:8081/api/v1/registry/scan
 *	Obtaining scan results:
 *		curl -k -u admin:admin https://localhost:8083/api/v1/registry?repository='scaledmarkets/taskruntime'
 *
 * Copyright Scaled Markets, Inc.
 */

package providers

import (
	"errors"
	"net/http"
	"fmt"

	//"bufio"
	//"bytes"
	"encoding/json"
	//"flag"
	"io"
	"io/ioutil"
	//"log"
	//"os"
	//"os/exec"
	//"strconv"
	"strings"
	"time"
	"strconv"

	// SafeHarbor packages:
	//"safeharbor/apitypes"
	"safeharbor/utils"

	"utilities/rest"
)

var ScanResultWaitIntervalMs = 100
var MaxNumberOfTries = 3
var NullTime = time.Time{}

type TwistlockService struct {
	UseSSL bool
	Host string
	Port int
	UserId string
	Password string
	//LocalIPAddress string  // of this machine, for Twistlock to call back
	Params map[string]string
}

func (twistlockSvc *TwistlockService) GetName() string { return "twistlock" }

func CreateTwistlockService(params map[string]interface{}) (ScanService, error) {
	
	var host string
	var portStr string
	var userId string
	var password string
	//var localIPAddress string
	var isType bool
	
	host, isType = params["Host"].(string)
	if host == "" { return nil, utils.ConstructUserError("Parameter 'Host' not specified") }
	if ! isType { return nil, utils.ConstructUserError("Parameter 'Host' is not a string") }

	portStr, isType = params["Port"].(string)
	if portStr == "" { return nil, utils.ConstructUserError("Parameter 'Port' not specified") }
	if ! isType { return nil, utils.ConstructUserError("Parameter 'Port' is not a string") }

	userId, isType = params["UserId"].(string)
	if userId == "" { return nil, utils.ConstructUserError("Parameter 'UserId' not specified") }
	if ! isType { return nil, utils.ConstructUserError("Parameter 'UserId' is not a string") }

	password, isType = params["Password"].(string)
	if password == "" { return nil, utils.ConstructUserError("Parameter 'Password' not specified") }
	if ! isType { return nil, utils.ConstructUserError("Parameter 'Password' is not a string") }
	
	//localIPAddress, isType = params["LocalIPAddress"].(string)
	//if localIPAddress == "" { return nil, utils.ConstructUserError("Parameter 'localIPAddress' not specified") }
	//if ! isType { return nil, utils.ConstructUserError("Parameter 'localIPAddress' is not a string") }
	
	var port int
	var err error
	port, err = strconv.Atoi(portStr)
	if err != nil { return nil, err }
	
	return &TwistlockService{
		UseSSL: true,
		Host: host,
		Port: port,
		UserId: userId,
		Password: password,
		//LocalIPAddress: localIPAddress,
		Params: map[string]string{},
	}, nil
}

func (twistlockSvc *TwistlockService) GetEndpoint() string {
	var scheme string
	if twistlockSvc.UseSSL {
		scheme = "https"
	} else {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s:%d/api/v1", scheme, twistlockSvc.Host, twistlockSvc.Port)
}

func (twistlockSvc *TwistlockService) GetParameterDescriptions() map[string]string {
	return twistlockSvc.Params
}

func (twistlockSvc *TwistlockService) GetParameterDescription(name string) (string, error) {
	var desc string = twistlockSvc.Params[name]
	if desc == "" { return "", utils.ConstructUserError("No parameter named '" + name + "'") }
	return desc, nil
}

func (twistlockSvc *TwistlockService) AsScanProviderDesc() *ScanProviderDesc {
	var params = []rest.ParameterInfo{}
	for name, desc := range twistlockSvc.Params {
		params = append(params, *rest.NewParameterInfo(name, desc))
	}
	return NewScanProviderDesc(twistlockSvc.GetName(), params)
}

/*******************************************************************************
 * For accessing the Twistlock scanning service.
 */
type TwistlockRestContext struct {
	rest.RestContext
	//MinimumVulnerabilityPriority string
	TwistlockService *TwistlockService
	sessionId string
}

var _ ScanContext = &TwistlockRestContext{}

func (twistlockSvc *TwistlockService) CreateScanContext(params map[string]string) (ScanContext, error) {
	
	//var minPriority string
	
	var scheme string
	if twistlockSvc.UseSSL { scheme = "https" } else { scheme = "http" }
	
	var context *TwistlockRestContext = &TwistlockRestContext{
		RestContext: *rest.CreateTCPRestContext(scheme,
			twistlockSvc.Host, twistlockSvc.Port, "", "", setTwistlockSessionId),
		//MinimumVulnerabilityPriority: minPriority,
		TwistlockService: twistlockSvc,
		sessionId: "",
	}
	
	var err = context.authenticate(twistlockSvc.UserId, twistlockSvc.Password)
	if err != nil {
		return nil, err
	}
	
	return context, nil
}

/*******************************************************************************
 * Authenticate to Twistlock server, to obtain session token and set it in the
 * REST context.
 * See https://twistlock.desk.com/customer/en/portal/articles/2831956-twistlock-api-2-1#authenticate
 */
func (twistlockContext *TwistlockRestContext) authenticate(userId string, password string) error {
	
	var response *http.Response
	var err error
	response, err = twistlockContext.SendSessionReq(
		twistlockContext.sessionId, "POST", twistlockContext.getEndpoint() + "/authenticate",
		[]string{ "username", "password" }, []string{ userId, password },
		[]string{ "Content-Type" }, []string{ "application/json" })
	if err != nil {
		return err
	}
	
	defer response.Body.Close()

	if response.StatusCode >= 300 {
		body, _ := ioutil.ReadAll(response.Body)
		return fmt.Errorf("Got response %d with message %s", response.StatusCode, string(body))
	}
	
	var jsonMap map[string]interface{}
	jsonMap, err = rest.ParseResponseBodyToMap(response.Body)
	if err != nil { return err }
	
	var obj = jsonMap["token"]
	if obj == nil {
		return errors.New("No token found in response")
	}
	
	var token string
	var isType bool
	token, isType = obj.(string)
	if ! isType {
		return errors.New("Token is not a string")
	}
	
	twistlockContext.sessionId = token
	
	return nil
}

func (twistlockContext *TwistlockRestContext) getEndpoint() string {
	return twistlockContext.TwistlockService.GetEndpoint()
}

func (twistlockContext *TwistlockRestContext) PingService() *rest.RestResponseType {
	var err = twistlockContext.PingConsole()
	if err != nil { return rest.NewRestResponseType(500, err.Error()) }
	return rest.NewRestResponseType(200, "Service is up")
}

/*******************************************************************************
 * 
 */
func (twistlockContext *TwistlockRestContext) ScanImage(imageName string) (*ScanResult, error) {
	
	fmt.Println("Initiating image scan")
	
	// Parse image name, to separate the registry name (if provided), and the repo path.
	var registryName string
	var repoPath string
	var err error
	registryName, repoPath, err = parseImageFullName(imageName)
	// If there is no registry name, it is assumed to be dockerhub.
	// The repo path includes the namespace. If the registyr is dockerhub, this
	// is the organization name.
	
	// Initiate scan.
	err = twistlockContext.initiateScan(registryName, repoPath)
	if err != nil {
		return nil, err
	}
	
	// Obtain scan results.
	/* Unfortunately, the scan call is non-blocking and there is no way to tell
		when it completes, so we have to poll.
		The call will return an array, in which the first object contains these elements:
			scanTime - time scan was performed, e.g., "2017-09-02T17:01:43.265Z".
			info.cveVulnerabilities - either null, or an array of objects containing
			these string-valued attributes:
				id
				link
				severity
				description
	*/
	var vulnerabilities []interface{}  // should be an array of maps
	var numberOfTries = 0
	for ;; { // until we obtain an up to date scan result, or reach max # of tries
		numberOfTries++
		if numberOfTries > MaxNumberOfTries {
			return nil, utils.ConstructUserError("Timed out waiting for scan result")
		}
		var scanCompletionTime time.Time
		vulnerabilities, scanCompletionTime, err = twistlockContext.getVulnerabilities(imageName);
		if err != nil {
			return nil, err
		}
		
		if scanCompletionTime.Before(time.Now()) {  // scan is the one that we initiated, or later
			break  // because we found a recent enough scan result
		}
		
		// Sleep for ScanResultWaitIntervalMs milliseconds.
		time.Sleep(time.Duration(ScanResultWaitIntervalMs) * time.Millisecond)
	}

	// Validate the result format, and construct a ScanResult object to return.
	var vulnDescs = make([]*VulnerabilityDesc, len(vulnerabilities))
	for i, vuln_ := range vulnerabilities {
		var vuln map[string]interface{}
		var isType bool
		vuln, isType = vuln_.(map[string]interface{})
		if ! isType {
			return nil, utils.ConstructUserError("Unexpected json object type for a cveVulnerability")
		}
		
		var id, link, severity, description string
		id, isType = vuln["id"].(string)
		if ! isType {
			return nil, utils.ConstructUserError("Unexpected json object type for vulnerability id")
		}
		link, isType = vuln["link"].(string)
		if ! isType {
			return nil, utils.ConstructUserError("Unexpected json object type for vulnerability link")
		}
		severity, isType = vuln["severity"].(string)
		if ! isType {
			return nil, utils.ConstructUserError("Unexpected json object type for vulnerability severity")
		}
		description, isType = vuln["description"].(string)
		if ! isType {
			return nil, utils.ConstructUserError("Unexpected json object type for vulnerability description")
		}
	
		vulnDescs[i] = NewVulnerabilityDesc(id, link, severity, description)
	}
	
	return &ScanResult{
		Vulnerabilities: vulnDescs,
	}, nil
}


/**************************** Twistlock Service Methods ***************************
 ******************************************************************************/


/*******************************************************************************
 * 
 */
func (twistlockContext *TwistlockRestContext) PingConsole() error {

	var response *http.Response
	var err error
	response, err = twistlockContext.SendSessionGet(
		twistlockContext.sessionId, twistlockContext.getEndpoint() + "/_ping", nil, nil)
	
	if response.StatusCode >= 300 {
		return errors.New(fmt.Sprintf("Returned %d", response.StatusCode))
	}
	
	return err
}


/**************************** Internal Implementation Methods ***************************
 ******************************************************************************/

//type APIVulnerabilitiesResponse struct {
//	Vulnerabilities []Vulnerability
//}

/*******************************************************************************
 * 
 */
func (twistlockContext *TwistlockRestContext) initiateScan(registryName, repoName string) error {
	
	/* Perform scan.
		The call to initiate a scan is of the form,
			curl -k -u admin:admin -H "Content-Type: application/json" \
				-d '{"tag":{"registry":"","repo":"scaledmarkets/taskruntime"}}' \
				-X POST https://localhost:8081/api/v1/registry/scan
	*/
	var jsonPayload string = fmt.Sprintf(
		"{\"tag\": {\"registry\": \"%s\", \"repo\": \"%s\"}}", registryName, repoName)
	
	var response *http.Response
	var stringReader io.Reader = strings.NewReader(jsonPayload)
	var err error
	response, err = twistlockContext.SendSessionStreamPost(
		twistlockContext.sessionId, "POST", twistlockContext.getEndpoint() + "/registry/scan",
		stringReader, []string{ "Content-Type" }, []string{ "application/json" })
	if err != nil {
		return err
	}
	
	defer response.Body.Close()

	if response.StatusCode >= 300 {
		body, _ := ioutil.ReadAll(response.Body)
		return fmt.Errorf("Got response %d with message %s", response.StatusCode, string(body))
	}
	
	return nil
}

/*******************************************************************************
 * Obtain the scan results for the specified image, and return the results
 * as an array of objects, where each object is expected to be a map of these values:
 	id
	link
	severity
	description
 * However, this method does not verify that the array elements conform to this.
 * Also return the time of the most recent scan of the image.
 */
func (twistlockContext *TwistlockRestContext) getVulnerabilities(
	imageName string) ([]interface{}, time.Time, error) {
	
	//....How come we don''t have to specify the registry?
	
	/*
		The call to obtain a scan result is of the form,
			curl -k -u admin:admin https://localhost:8083/api/v1/registry?repository='scaledmarkets/taskruntime'
	*/
	
	var response *http.Response
	var err error
	response, err = twistlockContext.SendSessionReq(
		twistlockContext.sessionId, "GET", twistlockContext.getEndpoint() + "/registry",
		[]string{"repository"}, []string{imageName}, nil, nil)
	if err != nil {
		return nil, NullTime, err
	}

	defer response.Body.Close()

	if response.StatusCode >= 300 {
		body, _ := ioutil.ReadAll(response.Body)
		return nil, NullTime, fmt.Errorf("Got response %d with message %s", response.StatusCode, string(body))
	}

	/*
		The body will contain a JSON array, in which the first object contains these elements:
			scanTime - time scan was performed, e.g., "2017-09-02T17:01:43.265Z".
			info.cveVulnerabilities - either null, or an array of objects containing
			these string-valued attributes:
				id
				link
				severity
				description
		We want to return the info.cveVulnerabilities array.
	 */
	
	// Parse the response - should be a JSON array.
	var responseAr []interface{}
	var value []byte
	value, err = ioutil.ReadAll(response.Body)
	if err != nil { return nil, NullTime, err }
	err = json.Unmarshal(value, &responseAr)
	if err != nil { return nil, NullTime, err }
	
	// Obtain the first array element.
	if len(responseAr) == 0 { return nil, NullTime, errors.New("No elements found in response array") }
	var firstObject map[string]interface{}
	var isType bool
	firstObject, isType = responseAr[0].(map[string]interface{})
	if ! isType {
		return nil, NullTime, errors.New("Did not find a map in the first element of the response array")
	}
	
	// Obtain scan time.
	var scanTime time.Time
	var obj = firstObject["scanTime"]
	if obj == nil {
		return nil, NullTime, errors.New("No scan time found")
	}
	var timeString string
	timeString, isType = obj.(string)
	if ! isType {
		return nil, NullTime, errors.New("scanTime is not a string")
	}
	scanTime, err = time.Parse(time.RFC3339, timeString)
	if err != nil {
		return nil, NullTime, errors.New("Error parsing time string: " + timeString)
	}

	// Obtain the vulnerability array.
	var info_ interface{} = firstObject["info"]  // should be an map[string]
	var info map[string]interface{}
	info, isType = info_.(map[string]interface{})
	if ! isType {
		return nil, NullTime, utils.ConstructUserError("Unexpected json object type for info field")
	}
	
	var vulnerabilities []interface{}
	var vulnerabilities_ interface{} = info["cveVulnerabilities"] // should be an array of objects
	if vulnerabilities_ == nil {
		// No vulnerabilities found.
		vulnerabilities = make([]interface{}, 0)
	} else {
		vulnerabilities, isType = vulnerabilities_.([]interface{})
		if ! isType {
			return nil, NullTime, utils.ConstructUserError("Unexpected json object type for cveVulnerabilities field")
		}
	}

	return vulnerabilities, scanTime, nil
}

/*******************************************************************************
 * 	Parse image name, to separate the registry name (if provided), and the repo path.
 */
func parseImageFullName(imageName string) (registryName string, repoPath string, err error) {
	
	var parts = strings.SplitN(imageName, "/", 2)
	if len(parts) == 0 {
		return "", "", errors.New("No name parts found in image name")
	}
	if len(parts) == 1 {
		return "", imageName, nil
	}
	if len(parts) > 2 {
		return "", "", errors.New("Internal error")
	}
	
	return parts[0], parts[1], nil
}

/*******************************************************************************
 * Set the session Id as a header token.
 */
func setTwistlockSessionId(req *http.Request, sessionId string) {
	
	req.Header.Set("Authorization", "Bearer " + sessionId)
}
