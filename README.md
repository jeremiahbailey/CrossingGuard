# CrossingGuard
CrossingGuard demonstrates a POC for detecting when a GCP SA has been given permissions to a resource outside of its environment. Since lots of GCP orgs use folders to create environments, there's often times a need to keep these environments separated as much as possible. Unless you are centralizing your IAM processes, it's hard to outright prevent a service account in one environment (dev) from being given permissions to another environment (prod, test, etc.). This is currently meant to be deployed as a Cloud Function that receives SetIAMPolicy events via a Pub/Sub but could be modified to be more active and scan an environment for cross-env grants.


## Design Space

1. When IAM binding event occurs validate that the ServiceAccounts in the binding are in fact in the same env as the node where the binding occured using IAM tags
2. If they are not, remove that service account from the binding.