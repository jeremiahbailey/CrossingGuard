// crossingguard is a package that looks for cross-evn IAM
// bindings on GCP and removes them.
package crossingguard

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"google.golang.org/api/iam/v1"

	crmv1 "google.golang.org/api/cloudresourcemanager/v1"
	crmv2 "google.golang.org/api/cloudresourcemanager/v2"
	"google.golang.org/api/cloudresourcemanager/v3"
)

// PubSubMessage is the payload of a Pub/Sub event.
// See the documentation for more details:
// https://cloud.google.com/pubsub/docs/reference/rest/v1/PubsubMessage
type PubSubMessage struct {
	Data []byte `json:"data"`
}

type SetIAMPolicyEvent struct {
	ProtoPayload struct {
		Type   string `json:"@type"`
		Status struct {
		} `json:"status"`
		AuthenticationInfo struct {
			PrincipalEmail string `json:"principalEmail"`
		} `json:"authenticationInfo"`
		RequestMetadata struct {
			CallerIP                string `json:"callerIp"`
			CallerSuppliedUserAgent string `json:"callerSuppliedUserAgent"`
			RequestAttributes       struct {
			} `json:"requestAttributes"`
			DestinationAttributes struct {
			} `json:"destinationAttributes"`
		} `json:"requestMetadata"`
		ServiceName       string `json:"serviceName"`
		MethodName        string `json:"methodName"`
		AuthorizationInfo []struct {
			Resource           string `json:"resource"`
			Permission         string `json:"permission"`
			Granted            bool   `json:"granted"`
			ResourceAttributes struct {
				Service string `json:"service"`
				Name    string `json:"name"`
				Type    string `json:"type"`
			} `json:"resourceAttributes"`
		} `json:"authorizationInfo"`
		ResourceName string `json:"resourceName"`
		ServiceData  struct {
			Type        string `json:"@type"`
			PolicyDelta struct {
				BindingDeltas []struct {
					Action string `json:"action"`
					Role   string `json:"role"`
					Member string `json:"member"`
				} `json:"bindingDeltas"`
			} `json:"policyDelta"`
		} `json:"serviceData"`
		Request struct {
			Resource string `json:"resource"`
			Type     string `json:"@type"`
			Policy   struct {
				Etag     string `json:"etag"`
				Bindings []struct {
					Members []string `json:"members"`
					Role    string   `json:"role"`
				} `json:"bindings"`
			} `json:"policy"`
			UpdateMask string `json:"updateMask"`
		} `json:"request"`
		Response struct {
			Type     string `json:"@type"`
			Etag     string `json:"etag"`
			Bindings []struct {
				Members []string `json:"members"`
				Role    string   `json:"role"`
			} `json:"bindings"`
		} `json:"response"`
	} `json:"protoPayload"`
	InsertID string `json:"insertId"`
	Resource struct {
		Type   string `json:"type"`
		Labels struct {
			ProjectID string `json:"project_id,omitempty"`
			FolderID  string `json:"folder_id,omitempty"`
		} `json:"labels"`
	} `json:"resource"`
	Timestamp        time.Time `json:"timestamp"`
	Severity         string    `json:"severity"`
	LogName          string    `json:"logName"`
	ReceiveTimestamp time.Time `json:"receiveTimestamp"`
}

var (
	event     SetIAMPolicyEvent
	folderIDs = make(map[string]bool)
	orgID     string
)

// unmarshallMessage unmarshalles the Pub/Sub message into the SetIAMPolicy struct.
func UnmarshallMessage(ctx context.Context, msg PubSubMessage) error {

	err := json.Unmarshal(msg.Data, &event)
	if err != nil {
		log.Println(fmt.Errorf("error unmarshalling message: %v", msg.Data))
	}

	switch {
	case event.Resource.Type == "folder":
		ProcessFolderEvent(ctx)
	case event.Resource.Type == "project":
		ProcessProjectEvent(ctx)
	}

	return nil
}

// compareServiceAccounts gets and compares the service accounts in the IAM Policy
// and the serviceAccounts in the project where the binding occurred.
func compareServiceAccounts(ctx context.Context, event SetIAMPolicyEvent) ([]string, error) {
	var policyServiceAccounts []string
	var projectServiceAccounts []string
	var susServiceAccounts []string

	// List serviceAccounts wants projectID in the format projects/{project-id}
	projectID := fmt.Sprintf("projects/%v", event.Resource.Labels.ProjectID)

	for _, v := range event.ProtoPayload.Response.Bindings {
		for _, v := range v.Members {
			if strings.Contains(v, "serviceAccount") {
				a := strings.Split(v, ":")[1]
				policyServiceAccounts = append(policyServiceAccounts, a)
			}
		}
	}

	// TODO need to eliminate service agents that aren't technically in the project but are associated with the project
	// we shouldn't count these as 'sus' accounts.

	// Create an IAM svc
	iamsvc, err := iam.NewService(ctx)
	if err != nil {
		log.Println(err)
	}
	// Get all the serviceAccounts in the project
	list := iamsvc.Projects.ServiceAccounts.List(projectID)
	resp, err := list.Do()
	if err != nil {
		log.Print(err)
	}
	// Append servieAccounts in the project to a []string
	for _, v := range resp.Accounts {
		projectServiceAccounts = append(projectServiceAccounts, v.Email)
	}

	for i := len(policyServiceAccounts) - 1; i >= 0; i-- {
		for _, vD := range projectServiceAccounts {
			if policyServiceAccounts[i] == vD {
				policyServiceAccounts = append(policyServiceAccounts[:i], policyServiceAccounts[i+1:]...)
				break
			}
		}
	}

	susServiceAccounts = policyServiceAccounts

	return susServiceAccounts, nil
}

//getAncestors returns the ancestors for the resource where the binding occurred.
func getAncestors(ctx context.Context) (map[string]string, error) {
	ancestors := make(map[string]string)

	// TODO getAncestry for a folder and not just a project.
	// if proejctid == ""{cloudresourcemanagerService.Folders.GetAncestry}
	// we would need to first check what type of event we have and have two
	// structs; one for each event to unmarshall the data properly.

	cloudresourcemanagerService, err := crmv1.NewService(ctx)
	if err != nil {
		return nil, err
	}
	// GetAncestry wants projectID in the format {project-id}
	projectID := event.Resource.Labels.ProjectID
	ancestryRequest := crmv1.GetAncestryRequest{}

	listProjects := cloudresourcemanagerService.Projects.GetAncestry(projectID, &ancestryRequest)
	req, err := listProjects.Do()
	if err != nil {
		log.Println(err)
	}

	for i, v := range req.Ancestor {
		// Since each key in a map must be unique and a project could have
		// multiple ancestors of the same type (e.g. folder) we need a way
		// to create a unique key while maintaining the type. This should also
		// help make it easy to understand which folder id is first in the hierarchy.
		ancestors[v.ResourceId.Type+fmt.Sprint(-i)] = v.ResourceId.Id
	}

	return ancestors, nil
}

//listProjects returns a list of the projects within the folder hierarch of the resource where
// the binding occurred.
func getAncestorProjects(ctx context.Context, ancestors map[string]string) ([]string, error) {

	var filter []string
	var project []*crmv1.Project
	var projectIDs []string

	cloudresourcemanagerService, err := crmv1.NewService(ctx)
	if err != nil {
		return nil, err
	}

	projectservice := crmv1.NewProjectsService(cloudresourcemanagerService)

	for k, v := range ancestors {
		if strings.Contains(k, "folder") {
			filter = append(filter, fmt.Sprintf("parent.type:folder parent.id:%v", v))
		}
	}

	for _, v := range filter {
		req, err := projectservice.List().Filter(v).Do()
		if err != nil {
			log.Println(err)
		}
		project = req.Projects
	}

	for _, v := range project {
		if v.LifecycleState == "ACTIVE" {
			projectIDs = append(projectIDs, v.ProjectId)
		}
	}
	return projectIDs, nil
}

// getServiceAccounts gets the service accounts in all the ancestors provided and compares them to the
// serviceAccounts in the binding that were not found in the project where the binding occurred.
func getAncestorServiceAccounts(ctx context.Context, projects []string, susServiceAccounts []string) ([]string, error) {
	var serviceAccounts []*iam.ServiceAccount
	var projectID string
	// Create an IAM svc
	iamsvc, err := iam.NewService(ctx)
	if err != nil {
		log.Println(err)
	}

	for _, v := range projects {

		// List serviceAccounts wants projectID in the format projects/{project-id}
		projectID = fmt.Sprintf("projects/%v", v)

		// Get all the serviceAccounts in the project
		list := iamsvc.Projects.ServiceAccounts.List(projectID)

		// TODO This can return an error if the API is not enabled in the target project.Maybe check if API is enabled first.
		resp, err := list.Do()
		if err != nil {
			log.Print(err)
		}

		serviceAccounts = resp.Accounts

		for i := len(susServiceAccounts) - 1; i >= 0; i-- {
			for _, vD := range serviceAccounts {
				if susServiceAccounts[i] == vD.Email {
					susServiceAccounts = append(susServiceAccounts[:i], susServiceAccounts[i+1:]...)
					break
				}
			}
		}
	}

	if len(susServiceAccounts) != 0 {
		log.Printf("These service accounts %v, were not found in any of these projects %v", susServiceAccounts, projectID)
	}

	return susServiceAccounts, nil
}

// search the top level folders under the org node and
// append to a list of folderIDs
func getTopLevelFolders(ctx context.Context) (map[string]bool, error) {

	crms, err := crmv2.NewService(ctx)
	folderSvc := crmv2.NewFoldersService(crms)
	if err != nil {
		return nil, err
	}
	query := fmt.Sprintf("parent=organizations/%s", orgID)
	searchfolders := crmv2.SearchFoldersRequest{
		Query: query,
	}
	req, err := folderSvc.Search(&searchfolders).Do()
	if err != nil {
		log.Println(err)
	}
	resp := req.Folders
	for _, v := range resp {
		folderIDs[v.Name] = false
	}
	return folderIDs, nil
}

// recursively search all folder ids under the top level folders
func getAllFolders(ctx context.Context, folderIDs map[string]bool) (map[string]bool, error) {
	var complete bool

	crms, err := crmv2.NewService(ctx)
	folderSvc := crmv2.NewFoldersService(crms)
	if err != nil {
		return nil, err
	}

	for k, v := range folderIDs {

		if !v {
			// set value to true so that we don't get the child of this folder again.
			folderIDs[k] = true
			searchfolders := crmv2.SearchFoldersRequest{
				Query: fmt.Sprintf("parent=%s", k),
			}
			req, err := folderSvc.Search(&searchfolders).Do()
			if err != nil {
				log.Println(err)
			}

			resp := req.Folders
			for _, v := range resp {
				folderIDs[v.Name] = false
			}
			complete = false
		}

		if v {
			complete = true
		}

	}

	if !complete {
		getAllFolders(ctx, folderIDs)
	}

	return folderIDs, nil

}

//getAllProjects appends the project IDs for all projects in GCP org to a []strings.
func getAllProjects(ctx context.Context, folderIDs map[string]bool) ([]string, error) {

	var projectIDs []string
	crms, err := crmv1.NewService(ctx)
	if err != nil {
		fmt.Println(err)
	}

	for k := range folderIDs {
		// filter wants only the folder id, we need to remove the folder/ component
		// of the folder name.
		folderID := strings.Split(k, "/")[1]
		filter := fmt.Sprintf("parent.type:folder parent.id:%v", folderID)
		req, err := crms.Projects.List().Filter(filter).Do()
		if err != nil {
			log.Printf("error getting projects in %v", folderID)
		}

		resp := req.Projects

		for _, v := range resp {
			if v.LifecycleState == "ACTIVE" {
				projectIDs = append(projectIDs, v.ProjectId)
			}
		}

	}
	orgFilter := fmt.Sprintf("parent.type:organization parent.id:%s", orgID)
	req, err := crms.Projects.List().Filter(orgFilter).Do()
	if err != nil {
		log.Printf("error getting projects in organization")
	}
	resp := req.Projects
	for _, v := range resp {
		if v.LifecycleState == "ACTIVE" {
			projectIDs = append(projectIDs, v.ProjectId)
		}
	}

	return projectIDs, nil
}

// getAllServiceAccounts gets all the service accounts in all projects in a GCP org.
func getAllServiceAccounts(ctx context.Context, projects []string) (map[string][]string, error) {
	var value []string
	serviceAccounts := make(map[string][]string)
	// Create an IAM svc
	iamsvc, err := iam.NewService(ctx)
	if err != nil {
		log.Println(err)
	}

	for _, v := range projects {

		// List serviceAccounts wants projectID in the format projects/{project-id}
		projectID := fmt.Sprintf("projects/%v", v)

		// Get all the serviceAccounts in the project
		req, err := iamsvc.Projects.ServiceAccounts.List(projectID).Do()
		if err != nil {
			log.Printf("Error getting project %v", projectID)
		}

		resp := req.Accounts

		for _, sa := range resp {
			value = serviceAccounts[v]
			value = append(value, sa.Email)
			serviceAccounts[v] = value
		}
	}

	log.Println(serviceAccounts)
	return serviceAccounts, nil
}

func serviceAccountProjectTag(serviceaccountproejctids map[string][]string, susServiceAccounts []string) {
	var projectIDs []string
	var tagValues []string

	m := make(map[string]string)
	// Check if the service accounts in the projects match the susServicesAccounts
	// If they do, we append the projectID of the project where the susServiceAccount
	// exists to a list of projectIDs.
	for projectid, serviceaccounts := range serviceaccountproejctids {
		for _, serviceaccount := range serviceaccounts {
			m[serviceaccount] = projectid
		}
	}

	for _, i := range susServiceAccounts {
		if _, ok := m[i]; ok {
			projectIDs = append(projectIDs, fmt.Sprintf("//cloudresourcemanager.googleapis.com/projects/%v", m[i]))
		}
	}

	projectIDs = append(projectIDs, fmt.Sprintf("//cloudresourcemanager.googleapis.com/projects/%v", event.Resource.Labels.ProjectID))

	ctx := context.Background()
	service, err := cloudresourcemanager.NewService(ctx)
	if err != nil {
		log.Println(err)
	}

	for _, projectID := range projectIDs {
		req, err := service.TagBindings.List().Parent(projectID).Do()
		if err != nil {
			log.Println(err)
		}

		resp := req.TagBindings

		for _, v := range resp {
			tagValues = append(tagValues, v.TagValue)
		}
	}

	for i := 0; i < len(tagValues)-1; i++ {
		if tagValues[i] != tagValues[i+1] {
			log.Printf("The tagValues do not match on the projects %v", projectIDs)
		}
	}
}

func ProcessFolderEvent(ctx context.Context) error {
	//TODO implement the right calls to get the ancestors, tags, etc. for when there is a setIamPolicy event on a folder.
	// May require restructuring the code to make this work efficiently.

	return nil
}

func ProcessProjectEvent(ctx context.Context) error {

	sa, err := compareServiceAccounts(ctx, event)
	if err != nil {
		log.Printf("error comparing service accounts: %v", err)
	}

	if len(sa) != 0 {
		ancestors, err := getAncestors(ctx)
		if err != nil {
			log.Printf("error getting ancestors: %v", err)
		}

		projects, err := getAncestorProjects(ctx, ancestors)
		if err != nil {
			log.Println("error getting projects", err)
		}
		sa, err := getAncestorServiceAccounts(ctx, projects, sa)
		if err != nil {
			log.Printf("error getting service accounts: %v", err)
		}
		log.Println(sa)
		tlf, err := getTopLevelFolders(ctx)
		if err != nil {
			log.Println(err)
		}
		folders, err := getAllFolders(ctx, tlf)
		if err != nil {
			log.Println(err)
		}

		projectIDs, err := getAllProjects(ctx, folders)
		if err != nil {
			log.Print(err)
		}

		allsas, err := getAllServiceAccounts(ctx, projectIDs)
		if err != nil {
			log.Println(err)
		}

		serviceAccountProjectTag(allsas, sa)
	}
	return nil
}
