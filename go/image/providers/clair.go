/*******************************************************************************
 * Implementation of ScanProvider for the CoreOS Clair container scanner.
 * See https://github.com/coreos/clair
 *
	// Clair scan:
	// https://github.com/coreos/clair
	// https://github.com/coreos/clair/tree/master/contrib/analyze-local-images
	
	From Clair maintainer (Quentin Machu):
	You don’t actually need to run Clair on each host, a single Clair instance/database
	is able to analyze all your container images. That is why it is an API-driven service.
	All Clair needs is being able to access your container images. When you insert
	a container layer via the API (https://github.com/coreos/clair/blob/master/docs/API.md#insert-a-new-layer),
	you have to specify a path to the layer tarball that Clair can access;
	it can either be a filesystem path or an URL. So you can analyze local images
	or images stored on S3, OpenStack Swift, Ceph pretty easily!
	
	You may want to take a look at https://github.com/coreos/clair/tree/master/contrib/analyze-local-images,
	a small tool I hacked to ease analyzing local images. But in fact, I added
	a very minimal “remote” support, allowing Clair to run somewhere else:
	the local images are served by a web server.
	
	Installing clair:
	docker pull quay.io/coreos/clair
	
	Running clair:
	sudo docker run -p 6060:6060 -p 6061:6061 -v /home/centos:/config:ro quay.io/coreos/clair:latest --config=/config/clairconfig.yaml
	old: sudo docker run -i -t -m 500M -v /tmp:/tmp -p 6060:6060 quay.io/coreos/clair:latest --db-type=bolt --db-path=/db/database
	
	For the analyze-local-images tool:
	sudo GOPATH=/home/vagrant go get -u github.com/coreos/clair/contrib/analyze-local-images
	/home/vagrant/bin/analyze-local-images <Docker Image ID>
	
	"ImageFormat": "Docker"
 *
 * Copyright Scaled Markets, Inc.
 */

package providers

import (
	//"errors"
	"net/http"
	//"net"
	"fmt"

	"bufio"
	"bytes"
	"encoding/json"
	//"flag"
	"io/ioutil"
	//"log"
	"os"
	"os/exec"
	//"strconv"
	"strings"
	//"time"
	"strconv"
	"path"
	//"time"
	
	// SafeHarbor packages:
	//"safeharbor/apitypes"
	"safeharbor/utils"
	
	"utilities/rest"
)

const (
	ImageRetrievalPort = 9279
)

type ClairService struct {
	UseSSL bool
	Host string
	Port int
	LocalIPAddress string  // of this machine, for clair to call back
	Params map[string]string
	ImageTarBaseDir string
}

func CreateClairService(params map[string]interface{}) (ScanService, error) {
	
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
	
	var tempDir string
	tempDir, err = utils.MakeTempDir()
	//tempDir, err = ioutil.TempDir("", "image-tars-for-clair")
	if err != nil { return nil, err }
	fmt.Println("Using dir " + tempDir + " for saving image layers")
	
	var clairSvc = &ClairService{
		UseSSL: false,
		Host: host,
		Port: port,
		LocalIPAddress: localIPAddress,
		ImageTarBaseDir: tempDir,
		Params: map[string]string{
			"MinimumPriority": "The minimum priority level of vulnerabilities to report",
		},
	}
	
	// Setup a simple HTTP server. This enables us to
	// provide the external Clair REST service with a URL for each layer.
	// To do: Use a separate non-public network adapter for this.
	fmt.Println("Starting HTTP service for clair to call to retrieve layers...")
	var imageRetrievalAddress = localIPAddress + ":" + strconv.Itoa(ImageRetrievalPort)
	go func(tarFileBaseDir string) {
		
		var allowedHost = host
		var portIndex int = strings.Index(allowedHost, ":")
		if portIndex >= 0 { allowedHost = allowedHost[:portIndex] }

		// Set up HTTP server allowing allowedHost.
		fmt.Println("Listening to Clair on " + imageRetrievalAddress)
		err := http.ListenAndServe(
			imageRetrievalAddress, restrictedFileServer(tarFileBaseDir, allowedHost))
		if err != nil {
			fmt.Println("- An error occurred with the HTTP Server: %s\n", err.Error())
		}
	}(tempDir)
	
	return clairSvc, nil
}

func (clairSvc *ClairService) GetName() string { return "clair" }

func (clairSvc *ClairService) GetEndpoint() string {
	return fmt.Sprintf("http://%s:%d", clairSvc.Host, clairSvc.Port)
}

func (clairSvc *ClairService) GetParameterDescriptions() map[string]string {
	return clairSvc.Params
}

func (clairSvc *ClairService) GetParameterDescription(name string) (string, error) {
	var desc string = clairSvc.Params[name]
	if desc == "" { return "", utils.ConstructUserError("No parameter named '" + name + "'") }
	return desc, nil
}

func (clairSvc *ClairService) AsScanProviderDesc() *ScanProviderDesc {
	var params = []rest.ParameterInfo{}
	for name, desc := range clairSvc.Params {
		params = append(params, *rest.NewParameterInfo(name, desc))
	}
	return NewScanProviderDesc(clairSvc.GetName(), params)
}

/*******************************************************************************
 * For accessing the Clair scanning service.
 */
type ClairRestContext struct {
	rest.RestContext
	MinimumVulnerabilityPriority string
	ClairService *ClairService
	sessionId string
	imageRetrievalIP string  // for clair to call back to, to get images
	imageRetrievalPort int  // for clair to call back to, to get images
}

var _ ScanContext = &ClairRestContext{}

func (clairSvc *ClairService) CreateScanContext(params map[string]string) (ScanContext, error) {
	
	var minPriority string
	
	if params != nil {
		minPriority = params["MinimumPriority"]
		// this param is optional so do not require its presence.
	}
	
	// Determine the IP address.
	var ipaddr = clairSvc.LocalIPAddress
	if ipaddr == "" {
		return nil, utils.ConstructServerError(
			"Did not find an IP4 address for clair to call back on")
	}
	
	var scheme string
	if clairSvc.UseSSL { scheme = "https" } else { scheme = "http" }
	
	return &ClairRestContext{
		RestContext: *rest.CreateTCPRestContext(scheme,
			clairSvc.Host, clairSvc.Port, "", "", setClairSessionId),
		MinimumVulnerabilityPriority: minPriority,
		ClairService: clairSvc,
		sessionId: "",
		imageRetrievalIP: ipaddr,
		imageRetrievalPort: ImageRetrievalPort,
			
	}, nil
}

func (clairContext *ClairRestContext) getEndpoint() string {
	return clairContext.ClairService.GetEndpoint()
}

func (clairContext *ClairRestContext) PingService() *rest.RestResponseType {
	var apiVersion string
	var engineVersion string
	var err error
	apiVersion, engineVersion, err = clairContext.GetVersions()
	if err != nil { return rest.NewRestResponseType(500, err.Error()) }
	return rest.NewRestResponseType(200, fmt.Sprintf(
		"Service is up: api version %s, engine version %s", apiVersion, engineVersion))
}

/*******************************************************************************
 * See https://github.com/coreos/clair/blob/master/contrib/analyze-local-images/main.go
 */
func (clairContext *ClairRestContext) ScanImage(imageName string) (*ScanResult, error) {
	
	// Use the docker 'save' command to extract image to a tar of tar files.
	// Must be extracted to a temp directory that is shared with the clair container.
	fmt.Printf("Saving %s\n", imageName)
	var tarFileRelDir string
	var err error
	tarFileRelDir, err = saveImageAsTars(clairContext.ClairService.ImageTarBaseDir, imageName)
	defer func() {
		fmt.Println("Removing all files at " + clairContext.ClairService.ImageTarBaseDir + tarFileRelDir)
		os.RemoveAll(tarFileRelDir)
	}()
	if err != nil { return nil, utils.PrintError(err) }
	var fullPath = clairContext.ClairService.ImageTarBaseDir + "/" + tarFileRelDir

	var tarDirURL = "http://" + clairContext.imageRetrievalIP + ":" +
		strconv.Itoa(clairContext.imageRetrievalPort) + "/" + tarFileRelDir

	// Retrieve image's layer Ids.
	fmt.Println("Getting image's layer Ids (aka 'history')...")
	var layerIds []string
	layerIds, err = historyFromManifest(fullPath)
	if err != nil {
		layerIds, err = historyFromCommand(imageName)
	}	
	
	if err != nil || len(layerIds) == 0 {
		return nil, utils.ConstructServerError("- Could not get image's history: " + err.Error())
	}
	
	// Analyze layers
	fmt.Printf("Analyzing %d layers\n", len(layerIds))
	var priorLayerId = ""
	for _, layerId := range layerIds {
		fmt.Printf("- Analyzing %s\n", layerId)
		var layerURL = tarDirURL + "/" + layerId + "/layer.tar"
		var err error
		err = analyzeLayer(clairContext.getEndpoint(), layerURL, layerId, priorLayerId)
		if err != nil { return nil, utils.PrintError(err) }
		priorLayerId = layerId
	}

	// Get vulnerabilities
	fmt.Println("Getting image's vulnerabilities")
	var vulnerabilities []Vulnerability
	vulnerabilities, err = getVulnerabilities(
		clairContext.getEndpoint(), layerIds[len(layerIds)-1], clairContext.MinimumVulnerabilityPriority)
	if err != nil { return nil, utils.PrintError(err) }
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


/**************************** Clair Service Methods ***************************
 ******************************************************************************/


/*******************************************************************************
 * 
 */
func (clairContext *ClairRestContext) GetVersions() (apiVersion string, engineVersion string, err error) {

	var resp *http.Response
	resp, err = clairContext.SendSessionGet(clairContext.sessionId, "v1/versions", nil, nil)
	
	if err != nil { return "", "", err }
	defer resp.Body.Close()
	
	clairContext.Verify200Response(resp)

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

func (clairContext *ClairRestContext) GetHealth() string {
	//resp = get("v1/health")
	return ""
}

func (clairContext *ClairRestContext) ProcessLayer(id, path, parentId string) error {
	var err error
	var resp *http.Response
	
	err = analyzeLayer(clairContext.getEndpoint(), path, id, parentId)
	
	if err != nil { return err }
	defer resp.Body.Close()
	
	clairContext.Verify200Response(resp)

	//var responseMap map[string]interface{}
	_, err  = rest.ParseResponseBodyToMap(resp.Body)
	if err != nil { return err }
	//var version string = responseMap["Version"]
	return nil
}

func (clairContext *ClairRestContext) GetLayerOS() {
}

func (clairContext *ClairRestContext) GetLayerParent() {
}

func (clairContext *ClairRestContext) GetLayerPackageList() {
}

func (clairContext *ClairRestContext) GetLayerPackageDiff() {
}

func (clairContext *ClairRestContext) GetLayerVulnerabilities() {
}

func (clairContext *ClairRestContext) GetLayerVulnerabilitiesDelta() {
}

func (clairContext *ClairRestContext) GetLayerVulnerabilitiesBatch() {
}

func (clairContext *ClairRestContext) GetVulnerabilityInfo() {
}

func (clairContext *ClairRestContext) GetLayersIntroducingVulnerability() {
}

func (clairContext *ClairRestContext) GetLayersAffectedByVulnerability() {
}


/**************************** Internal Implementation Methods ***************************
 ******************************************************************************/



const (
	postLayerURI               = "/v1/layers"
	getLayerVulnerabilitiesURI = "/v1/layers/%s?vulnerabilities"
)

type APIVulnerabilitiesResponse struct {
	Vulnerabilities []Vulnerability
}

/*******************************************************************************
 * Set the session Id as a cookie.
 */
func setClairSessionId(req *http.Request, sessionId string) {
	
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

/*******************************************************************************
 * Retrieve image as a tar of tars, and extract each tar (layer).
 * Return the path to the directory containing the layer tar files,
 * relative to imageTarBaseDir.
 */
func saveImageAsTars(imageTarBaseDir, imageName string) (string, error) {
	
	fullPath, err := utils.MakeTempDir()
	//fullPath, err := ioutil.TempDir(imageTarBaseDir, "layers")
		if err != nil { return "", err }
		
	var stderr bytes.Buffer
	save := exec.Command("docker", "save", imageName)
	save.Stderr = &stderr
	
	extract := exec.Command("tar", "xf", "-", "-C" + fullPath)
	extract.Stderr = &stderr
	
	pipe, err := extract.StdinPipe()
		if err != nil { return "", err }
	
	save.Stdout = pipe

	err = extract.Start()  // does not block
		if err != nil { return "", utils.ConstructServerError(stderr.String()) }
	
	err = save.Run()  // blocks until done
		if err != nil { return "", utils.ConstructServerError(stderr.String()) }
	
	err = pipe.Close()
		if err != nil { return "", err }
	
	err = extract.Wait()
		if err != nil { return "", utils.ConstructServerError(stderr.String()) }
		
	return path.Base(fullPath), nil
}

/*******************************************************************************
 * 
 */
func historyFromManifest(path string) ([]string, error) {
	mf, err := os.Open(path + "/manifest.json")
	if err != nil {
		return nil, err
	}
	defer mf.Close()

	// https://github.com/docker/docker/blob/master/image/tarexport/tarexport.go#L17
	type manifestItem struct {
		Config   string
		RepoTags []string
		Layers   []string
	}

	var manifest []manifestItem
	if err = json.NewDecoder(mf).Decode(&manifest); err != nil {
		return nil, err
	} else if len(manifest) != 1 {
		return nil, err
	}
	var layers []string
	for _, layer := range manifest[0].Layers {
		layers = append(layers, strings.TrimSuffix(layer, "/layer.tar"))
	}
	return layers, nil
}

/*******************************************************************************
 * 
 */
func historyFromCommand(imageName string) ([]string, error) {
	var stderr bytes.Buffer
	cmd := exec.Command("docker", "history", "-q", "--no-trunc", imageName)
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return []string{}, err
	}

	err = cmd.Start()
	if err != nil {
		return []string{}, utils.ConstructServerError(stderr.String())
	}

	var layers []string
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		layers = append(layers, scanner.Text())
	}

	for i := len(layers)/2 - 1; i >= 0; i-- {
		opp := len(layers) - 1 - i
		layers[i], layers[opp] = layers[opp], layers[i]
	}

	return layers, nil
}

/*******************************************************************************
 * 
 */
func analyzeLayer(endpoint, path, layerName, parentLayerName string) error {
	
	var jsonPayload string = fmt.Sprintf("{\"Layer\": {" +
		"\"Name\": \"%s\", " +
		"\"Path\": \"%s\", " +
		"\"ParentName\": \"%s\", " +
		"\"Format\": \"%s\"}}",
		layerName, path, parentLayerName, "Docker")
	
	var url = endpoint + postLayerURI
	fmt.Println("Sending request to clair:")
	fmt.Println("POST " + url + " " + string(jsonPayload))

	request, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(jsonPayload)))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != 201 {
		body, _ := ioutil.ReadAll(response.Body)
		return fmt.Errorf("Got response %d with message %s", response.StatusCode, string(body))
	}

	return nil
}

/*******************************************************************************
 * 
 */
func getVulnerabilities(endpoint, layerID, minimumPriority string) ([]Vulnerability, error) {
	
	var url = endpoint + fmt.Sprintf(getLayerVulnerabilitiesURI, layerID)
	fmt.Println(url)
	
	response, err := http.Get(url)
	if err != nil {
		return []Vulnerability{}, err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		body, _ := ioutil.ReadAll(response.Body)
		return []Vulnerability{}, fmt.Errorf("Got response %d with message %s", response.StatusCode, string(body))
	}

	var apiResponse APIVulnerabilitiesResponse
	err = json.NewDecoder(response.Body).Decode(&apiResponse)
	if err != nil {
		return []Vulnerability{}, err
	}

	return apiResponse.Vulnerabilities, nil
}

/*******************************************************************************
 * 
 */
func restrictedFileServer(path, allowedHost string) http.Handler {
	fmt.Println("Setting up file server for Clair, rooted at " + path)
	fc := func(w http.ResponseWriter, r *http.Request) {
		//if r.Host == allowedHost {
			fmt.Println("Received request for URI: " + r.RequestURI)
			http.FileServer(http.Dir(path)).ServeHTTP(w, r)
			return
		//}
		//w.WriteHeader(403)
	}
	return http.HandlerFunc(fc)
}