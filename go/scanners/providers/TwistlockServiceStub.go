/*******************************************************************************
 * Implementation of ScanProvider for the Twistlock container scanner.
 * See:
 *	https://twistlock.desk.com/customer/en/portal/topics/876139-twistlock-api/articles
 *	https://twistlock.desk.com/customer/en/portal/articles/2831956-twistlock-api-2-1
 *		(See "Selective Repository Scan")
 *
 * Copyright Scaled Markets, Inc.
 */

package providers

import (
	"net/http"
	"fmt"
	"strconv"

	// SafeHarbor packages:
	//"safeharbor/apitypes"
	"safeharbor/utils"

	"utilities/rest"
)

type TwistlockServiceStub struct {
	UseSSL bool
	Host string
	Port int
	LocalIPAddress string  // of this machine, for Twistlock to call back
	Params map[string]string
}

func (twistlockSvc *TwistlockServiceStub) GetName() string { return "twistlock" }

func CreateTwistlockServiceStub(params map[string]interface{}) (ScanService, error) {
	
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
	
	return &TwistlockServiceStub{
		UseSSL: false,
		Host: host,
		Port: port,
		//LocalIPAddress: localIPAddress,
		Params: map[string]string{
			"UserId": "User id for connecting to the Twistlock server",
			"Password": "Password for connecting to the Twistlock server",
		},
	}, nil
}

func (twistlockSvc *TwistlockServiceStub) GetEndpoint() string {
	var scheme string
	if twistlockSvc.UseSSL {
		scheme = "https"
	} else {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s:%d/api/v1", scheme, twistlockSvc.Host, twistlockSvc.Port)
}

func (twistlockSvc *TwistlockServiceStub) GetParameterDescriptions() map[string]string {
	return twistlockSvc.Params
}

func (twistlockSvc *TwistlockServiceStub) GetParameterDescription(name string) (string, error) {
	var desc string = twistlockSvc.Params[name]
	if desc == "" { return "", utils.ConstructUserError("No parameter named '" + name + "'") }
	return desc, nil
}

func (twistlockSvc *TwistlockServiceStub) CreateScanContext(params map[string]string) (ScanContext, error) {
	
	var scheme string
	if twistlockSvc.UseSSL { scheme = "https" } else { scheme = "http" }
	
	var context *TwistlockRestContextStub = &TwistlockRestContextStub{
		RestContext: *rest.CreateTCPRestContext(scheme,
			twistlockSvc.Host, twistlockSvc.Port, "", "", setTwistlockStubSessionId),
		//MinimumVulnerabilityPriority: minPriority,
		TwistlockServiceStub: twistlockSvc,
		sessionId: "",
	}
	
	return context, nil
}

func (twistlockSvc *TwistlockServiceStub) AsScanProviderDesc() *ScanProviderDesc {
	var params = []rest.ParameterInfo{}
	for name, desc := range twistlockSvc.Params {
		params = append(params, *rest.NewParameterInfo(name, desc))
	}
	return NewScanProviderDesc(twistlockSvc.GetName(), params)
}

/*******************************************************************************
 * For accessing the Twistlock scanning service.
 */
type TwistlockRestContextStub struct {
	rest.RestContext
	MinimumVulnerabilityPriority string
	TwistlockServiceStub *TwistlockServiceStub
	sessionId string
}

func (twistlockContext *TwistlockRestContextStub) getEndpoint() string {
	return twistlockContext.TwistlockServiceStub.GetEndpoint()
}

func (twistlockContext *TwistlockRestContextStub) PingService() *rest.RestResponseType {
	return rest.NewRestResponseType(200, "Service is up")
}

/*******************************************************************************
 * 
 */
func (twistlockContext *TwistlockRestContextStub) ScanImage(imageName string) (*ScanResult, error) {
	
	// Use Twistlock API method "registry/scan".
	// POST /api/v1/registry/scan

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



/**************************** Internal Implementation Methods ***************************
 ******************************************************************************/



/*******************************************************************************
 * Set the session Id as a header token.
 */
func setTwistlockStubSessionId(req *http.Request, sessionId string) {
	
	req.Header.Set("Authorization", "Bearer " + sessionId)
}
