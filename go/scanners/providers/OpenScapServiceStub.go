/*******************************************************************************
 * Implementation of ScanProvider for the OpenScap container scanner.
 * See:
 *	https://github.com/OpenSCAP/openscap-daemon
 *	https://github.com/mvazquezc/oscap-daemon-api
 *	http://static.open-scap.org/openscap-1.2/oscap_user_manual.html#_scanning_of_docker_containers_and_images_using_oscap_docker
 *	https://developers.redhat.com/blog/2016/05/02/introducing-atomic-scan-container-vulnerability-detection/
 *
 * Copyright Scaled Markets, Inc.
 */

package providers

import (
	//"errors"
	"net/http"
	"fmt"

	//"bufio"
	//"bytes"
	//"encoding/json"
	//"flag"
	//"io/ioutil"
	//"log"
	//"os"
	//"os/exec"
	//"strconv"
	//"strings"
	//"time"
	"strconv"

	// SafeHarbor packages:
	//"safeharbor/apitypes"
	"safeharbor/utils"

	"utilities/rest"
)

type OpenScapServiceStub struct {
	UseSSL bool
	Host string
	Port int
	LocalIPAddress string  // of this machine, for OpenScap to call back
	Params map[string]string
}

func (openScapSvc *OpenScapServiceStub) GetName() string { return "openscap" }

func CreateOpenScapServiceStub(params map[string]interface{}) (ScanService, error) {
	
	var host string
	var portStr string
	var localIPAddress string
	var isType bool
	
	host, isType = params["Host"].(string)
	if host == "" { return nil, utils.ConstructUserError("Parameter 'Host' not specified") }
	if ! isType { return nil, utils.ConstructUserError("Parameter 'Host' is not a string") }

	portStr, isType = params["Port"].(string)
	if portStr == "" { return nil, utils.ConstructUserError("Parameter 'Port' not specified") }
	if ! isType { return nil, utils.ConstructUserError("Parameter 'Port' is not a string") }

	localIPAddress, isType = params["LocalIPAddress"].(string)
	if localIPAddress == "" { return nil, utils.ConstructUserError("Parameter 'localIPAddress' not specified") }
	if ! isType { return nil, utils.ConstructUserError("Parameter 'localIPAddress' is not a string") }
	
	var port int
	var err error
	port, err = strconv.Atoi(portStr)
	if err != nil { return nil, err }
	
	return &OpenScapServiceStub{
		UseSSL: false,
		Host: host,
		Port: port,
		LocalIPAddress: localIPAddress,
		Params: map[string]string{
			"MinimumPriority": "The minimum priority level of vulnerabilities to report",
		},
	}, nil
}

func (openScapSvc *OpenScapServiceStub) GetEndpoint() string {
	return fmt.Sprintf("http://%s:%d", openScapSvc.Host, openScapSvc.Port)
}

func (openScapSvc *OpenScapServiceStub) GetParameterDescriptions() map[string]string {
	return openScapSvc.Params
}

func (openScapSvc *OpenScapServiceStub) GetParameterDescription(name string) (string, error) {
	var desc string = openScapSvc.Params[name]
	if desc == "" { return "", utils.ConstructUserError("No parameter named '" + name + "'") }
	return desc, nil
}

func (openScapSvc *OpenScapServiceStub) CreateScanContext(params map[string]string) (ScanContext, error) {
	
	var minPriority string
	
	if params != nil {
		minPriority = params["MinimumPriority"]
		// this param is optional so do not require its presence.
	}
	
	var scheme string
	if openScapSvc.UseSSL { scheme = "https" } else { scheme = "http" }
	
	return &OpenScapRestContextStub{
		RestContext: *rest.CreateTCPRestContext(scheme,
			openScapSvc.Host, openScapSvc.Port, "", "", setOpenScapSessionStubId),
		MinimumVulnerabilityPriority: minPriority,
		OpenScapServiceStub: openScapSvc,
		sessionId: "",
	}, nil
}

func (openScapSvc *OpenScapServiceStub) AsScanProviderDesc() *ScanProviderDesc {
	var params = []rest.ParameterInfo{}
	for name, desc := range openScapSvc.Params {
		params = append(params, *rest.NewParameterInfo(name, desc))
	}
	return NewScanProviderDesc(openScapSvc.GetName(), params)
}

/*******************************************************************************
 * For accessing the OpenScap scanning service.
 */
type OpenScapRestContextStub struct {
	rest.RestContext
	MinimumVulnerabilityPriority string
	OpenScapServiceStub *OpenScapServiceStub
	sessionId string
}

func (openScapContext *OpenScapRestContextStub) getEndpoint() string {
	return openScapContext.OpenScapServiceStub.GetEndpoint()
}

func (openScapContext *OpenScapRestContextStub) PingService() *rest.RestResponseType {
	var apiVersion string
	var engineVersion string
	var err error
	apiVersion, engineVersion, err = openScapContext.GetVersions()
	if err != nil { return rest.NewRestResponseType(500, err.Error()) }
	return rest.NewRestResponseType(200, fmt.Sprintf(
		"Service is up: api version %s, engine version %s", apiVersion, engineVersion))
}

/*******************************************************************************
 * 
 */
func (openScapContext *OpenScapRestContextStub) ScanImage(imageName string) (*ScanResult, error) {
	
	// Save image
	fmt.Printf("Saving %s\n", imageName)

	// Retrieve history
	fmt.Println("Getting image's history")

	// Analyze layers
	fmt.Printf("Analyzing layers")

	// Get vulnerabilities
	fmt.Println("Getting image's vulnerabilities")
	var vulnerabilities = []Vulnerability{
		Vulnerability{
			ID: "12345-XYZ-4",
			Link: "http://somewhere.cert.org",
			Priority: "High",
			Description: "A very bad vulnerability",
		},
	}
	if len(vulnerabilities) == 0 {
		fmt.Println("No vulnerabilities found for image")
	}
	for _, vulnerability := range vulnerabilities {
		fmt.Printf("- # %s\n", vulnerability.ID)
		fmt.Printf("  - Priority:    %s\n", vulnerability.Priority)
		fmt.Printf("  - Link:        %s\n", vulnerability.Link)
		fmt.Printf("  - Description: %s\n", vulnerability.Description)
	}

	var vulnDescs = make([]*VulnerabilityDesc, len(vulnerabilities))
	for i, vuln := range vulnerabilities {
		vulnDescs[i] = NewVulnerabilityDesc(
			vuln.ID, vuln.Link, vuln.Priority, vuln.Description)
	}
	
	return &ScanResult{
		Vulnerabilities: vulnDescs,
	}, nil
}


/**************************** OpenScap Service Methods ***************************
 ******************************************************************************/


/*******************************************************************************
 * 
 */
func (openScapContext *OpenScapRestContextStub) GetVersions() (apiVersion string, engineVersion string, err error) {

	var resp *http.Response
	resp, err = openScapContext.SendSessionGet(openScapContext.sessionId, "v1/versions", nil, nil)
	
	if err != nil { return "", "", err }
	defer resp.Body.Close()
	
	openScapContext.Verify200Response(resp)

	var responseMap map[string]interface{}
	responseMap, err = rest.ParseResponseBodyToMap(resp.Body)
	if err != nil { return "", "", err }
	var isType bool
	apiVersion, isType = responseMap["APIVersion"].(string)
	if ! isType { return "", "", utils.ConstructServerError("Value returned for APIVersion is not a string") }
	engineVersion, isType = responseMap["EngineVersion"].(string)
	if ! isType { return "", "", utils.ConstructServerError("Value returned for EngineVersion is not a string") }
	return apiVersion, engineVersion, nil
}

func (openScapContext *OpenScapRestContextStub) GetHealth() string {
	//resp = get("v1/health")
	return ""
}


/**************************** Internal Implementation Methods ***************************
 ******************************************************************************/



/*******************************************************************************
 * Set the session Id as a cookie.
 */
func setOpenScapSessionStubId(req *http.Request, sessionId string) {
	
	// Set cookie containing the session Id.
	var cookie = &http.Cookie{
		Name: "SessionId",
		Value: sessionId,
		//Path: 
		//Domain: 
		//Expires: 
		//RawExpires: 
		MaxAge: 86400,
		Secure: false,  //....change to true later.
		HttpOnly: true,
		//Raw: 
		//Unparsed: 
	}
	
	req.AddCookie(cookie)
}
