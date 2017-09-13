package providers

import (
	
	"fmt"
	"utilities/rest"
)

type ScanService interface {
	GetName() string
	GetEndpoint() string
	GetParameterDescriptions() map[string]string
	GetParameterDescription(string) (string, error)
	CreateScanContext(map[string]string) (ScanContext, error)  // params may be nil
	AsScanProviderDesc() *ScanProviderDesc
}

type ScanContext interface {
	PingService() *rest.RestResponseType
	ScanImage(string) (*ScanResult, error)
}

type ScanResult struct {
	Vulnerabilities []*VulnerabilityDesc
}

/*******************************************************************************
 * 
 */
type ScanProviderDesc struct {
	rest.RestResponseType
	ProviderName string
	Parameters []rest.ParameterInfo
}

func NewScanProviderDesc(name string, params []rest.ParameterInfo) *ScanProviderDesc {
	return &ScanProviderDesc{
		RestResponseType: *rest.NewRestResponseType(200, "OK"),
		ProviderName: name,
		Parameters: params,
	}
}

func (scanProviderDesc *ScanProviderDesc) AsJSON() string {
	var response string = fmt.Sprintf(" {%s, \"Name\": \"%s\", \"Parameters\": [",
		scanProviderDesc.RestResponseTypeFieldsAsJSON(), scanProviderDesc.ProviderName)
	var firstTime bool = true
	for _, paramInfo := range scanProviderDesc.Parameters {
		if firstTime { firstTime = false } else { response = response + ",\n" }
		response = response + paramInfo.AsJSON()
	}
	response = response + "]}"
	return response
}

type ScanProviderDescs []*ScanProviderDesc

func (scanProviderDescs ScanProviderDescs) AsJSON() string {
	var response string = " {" + rest.HttpOKResponse() + ", \"payload\": [\n"
	var firstTime bool = true
	for _, desc := range scanProviderDescs {
		if firstTime { firstTime = false } else { response = response + ",\n" }
		response = response + desc.AsJSON()
	}
	response = response + "]}"
	return response
}

func (providerDescs ScanProviderDescs) SendFile() (string, bool) {
	return "", false
}

/*******************************************************************************
 * 
 */
type Vulnerability struct {
	ID, Link, Priority, Description string
}

type VulnerabilityDesc struct {
	VCE_ID, Link, Priority, Description string
}

func NewVulnerabilityDesc(vCE_ID, link, priority, description string) *VulnerabilityDesc {
	return &VulnerabilityDesc{
		VCE_ID: vCE_ID,
		Link: link,
		Priority: priority,
		Description: description,
	}
}

func (vulnDesc *VulnerabilityDesc) AsJSON() string {
	return fmt.Sprintf(" {\"VCE_ID\": \"%s\", \"Link\": \"%s\", \"Priority\": \"%s\", " +
		"\"Description\": \"%s\"}",
		vulnDesc.VCE_ID, vulnDesc.Link, vulnDesc.Priority, vulnDesc.Description)
}

	/*
	Lynis:
		// Lynis scan:
		// https://cisofy.com/lynis/
		// https://cisofy.com/lynis/plugins/docker-containers/
		// /usr/local/lynis/lynis -c --checkupdate --quiet --auditor "SafeHarbor" > ....
	Baude:
		// OpenScap using RedHat/Baude image scanner:
		// https://github.com/baude/image-scanner
		// https://github.com/baude
		// https://developerblog.redhat.com/2015/04/21/introducing-the-atomic-command/
		// https://access.redhat.com/articles/881893#get
		// https://aws.amazon.com/partners/redhat/
		// https://aws.amazon.com/marketplace/pp/B00VIMU19E
		// https://aws.amazon.com/marketplace/library/ref=mrc_prm_manage_subscriptions
		// RHEL7.1 ami at Amazon: ami-4dbf9e7d
		
		//var cmd *exec.Cmd = exec.Command("image-scanner-remote.py",
		//	"--profile", "localhost", "-s", dockerImage.getDockerImageTag())
	openscap:
		// http://www.open-scap.org/resources/documentation/security-compliance-of-rhel7-docker-containers/
		
	*/
