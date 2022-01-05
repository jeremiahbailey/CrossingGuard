// crossingguard is a package that looks for cross-evn IAM
// bindings on GCP and removes them.
package crossingguard

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"google.golang.org/api/iam/v1"

	crmv1 "google.golang.org/api/cloudresourcemanager/v1"
	crmv2 "google.golang.org/api/cloudresourcemanager/v2"
	"google.golang.org/api/cloudresourcemanager/v3"
)

/* TODO REFACTORING

Separate into different packages.

There are a couple basic processes that this does:
1. Identify sus serviceAccounts
2. Get project/folders in the org
3. Determine the tags on the resource(s)
4. (TBD) Remove the serviceAccount(s) from the IAM policy



Look for areas to simplify the approach, implement methods, rename vars to be more
readable and avoid confusion w/ similarly named vars (may be aided by separating into diff packages).



*/

var (
	event     SetIAMPolicyEvent
	folderIDs        = make(map[string]bool)
	orgID     string = "218422761942"
)

// unmarshallMessage unmarshalles the Pub/Sub message into the SetIAMPolicy struct.
func UnmarshallMessage(ctx context.Context, msg PubSubMessage) error {
	log.Println("inside UnmarshalMessage()")
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
	log.Println("inside compareServiceAccounts()")
	var policyServiceAccounts []string
	var projectServiceAccounts []string
	var susServiceAccounts []string

	// List serviceAccounts wants projectID in the format projects/{project-id}
	projectID := fmt.Sprintf("projects/%v", event.Resource.Labels.ProjectID)

	for _, v := range event.ProtoPayload.Response.Bindings {
		for _, v := range v.Members {
			if strings.Contains(v, "serviceAccount") && !strings.Contains(v, "service-") {
				a := strings.Split(v, ":")[1]
				policyServiceAccounts = append(policyServiceAccounts, a)
			}
		}
	}

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
	log.Println("inside getAncestors()")
	ancestors := make(map[string]string)

	cloudresourcemanagerService, err := crmv1.NewService(ctx)
	ancestryRequest := crmv1.GetAncestryRequest{}
	if err != nil {
		return nil, err
	}

	// GetAncestry wants projectID in the format {project-id}
	projectID := event.Resource.Labels.ProjectID

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
	log.Println("inside getAncestorProjects()")
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
	log.Println("inside getAncestorServiceA()")
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
	log.Println("inside toplevelfolders()")
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
	log.Println("inside getallfolders()")
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
	log.Println("inside getAllProjects()")
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

// func getProjects(ctx context.Context) ([]string, error) {
// 	var projectIDs []string
// 	c, err := asset.NewClient(ctx)
// 	if err != nil {
// 		return nil, fmt.Errorf("error building asset client %v", err)
// 	}
// 	var req *assetpb.SearchAllResourcesRequest
// 	req.Scope
// 	c.SearchAllResources(ctx)

// 	return projectIDs, nil
// }

// getAllServiceAccounts gets all the service accounts in all projects in a GCP org.
func getAllServiceAccounts(ctx context.Context, projects []string) (map[string][]string, error) {
	log.Println("Inside getallserviceaccounts")
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

func serviceAccountProjectTag(serviceaccountproejctids map[string][]string, susServiceAccounts []string) ([]string, error) {
	log.Println("inside serviceaccountProjectTag")
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
		return nil, fmt.Errorf("error building resource manager service %v", err)
	}

	for _, projectID := range projectIDs {
		req, err := service.TagBindings.List().Parent(projectID).Do()
		if err != nil {
			return nil, fmt.Errorf("error getting tags %v", err)
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
	return susServiceAccounts, nil
}

func removeSusServiceAccounts(susServiceAccounts []string) error {
	// Deleting the Service Account from the policy

	/*
	   Then we need to find that service account in the event body, and determine if it's the only member of a given role.
	   If it's the only member of that role we can remove that entirely from  the []bindings, otherwise we just need to remove
	   that service account from the []members within that []bindings to make a new setIAMPolicy request to the API.
	   Note that this will be based on the resource (folder/projectFirst, we need to hold on to the service account in question.) where the event occurred since this is a part of the
	   resource manager API and not the IAM API.

	*/
	log.Println("inside removeSusServiceAccounts()")
	projectID := event.Resource.Labels.ProjectID
	bindings := event.ProtoPayload.Request.Policy.Bindings

	var setIAMPolicyRequest *cloudresourcemanager.SetIamPolicyRequest
	var policy *cloudresourcemanager.Policy
	var crmBinding *cloudresourcemanager.Binding

	// this will turn any member in the policy that is a susServiceAccount to a "". Unsure if this will be accepted by the API.
	for _, v := range bindings {
		for i, member := range v.Members {
			if member == susServiceAccounts[i] {
				log.Println(member)
				v.Members[i] = ""
				log.Println(member)

				crmBinding.Members = v.Members
				crmBinding.Role = v.Role

				policy.Bindings = []*cloudresourcemanager.Binding{crmBinding}
				policy.Version = 3
			}

		}
	}

	setIAMPolicyRequest.Policy = policy
	// build resource manager policy object from bindings
	// build request to set IAM policy, send request.

	ctx := context.Background()
	svc, err := cloudresourcemanager.NewService(ctx)
	if err != nil {
		return fmt.Errorf("error creating resource manager servicer: %v", err)
	}
	prjSvc := cloudresourcemanager.NewProjectsService(svc)
	req := prjSvc.SetIamPolicy(fmt.Sprintf("projects/%v", projectID), setIAMPolicyRequest)

	res, err := req.Do()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(res.HTTPStatusCode)
	return nil
}

func ProcessFolderEvent(ctx context.Context) error {
	sa, err := compareServiceAccounts(ctx, event)
	if err != nil {
		return fmt.Errorf("error comparing service accounts: %v", err)
	}

	if len(sa) != 0 {

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

		acc, err := serviceAccountProjectTag(allsas, sa)
		if err != nil {
			log.Println(err)
		}
		removeSusServiceAccounts(acc)
	}
	return nil
}
