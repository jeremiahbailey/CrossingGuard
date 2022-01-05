package crossingguard

import "time"

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
