package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/cloudflare/cfssl/csr"
	"k8s.io/api/certificates/v1beta1"
	"k8s.io/api/core/v1"

	"encoding/json"
	"encoding/pem"
	"io/ioutil"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/minikube/pkg/util/kubeconfig"

	// "k8s.io/kops/pkg/kubeconfig"

	"github.com/gorilla/mux"
)

var clusterName string

func init() {
	clusterName = os.Getenv("CLUSTER_NAME")
}

func genCsr(namespace string, username string) ([]byte, []byte) {

	name := csr.Name{
		C:  "US",
		ST: "Virginia",
		L:  "Richmond",
		O:  "faas",
		OU: "devops",
	}

	keyRequest := csr.NewBasicKeyRequest()
	keyRequest.A = "rsa"
	keyRequest.S = 2048

	csrq := csr.CertificateRequest{
		CN:         username,
		Names:      []csr.Name{name},
		KeyRequest: keyRequest,
	}

	csr, key, _ := csr.ParseRequest(&csrq)
	// fmt.Println(string(csr[:]))
	// fmt.Println(string(key[:]))
	return csr, key
}

func createCertificate(user, namespace string, request []byte, clientset *kubernetes.Clientset) *v1beta1.CertificateSigningRequest {

	csrClient := clientset.CertificatesV1beta1().CertificateSigningRequests()
	csr := &v1beta1.CertificateSigningRequest{
		TypeMeta: metav1.TypeMeta{
			Kind:       "CertificateSigningRequest",
			APIVersion: "certificates.k8s.io/v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: user,
		},
		Spec: v1beta1.CertificateSigningRequestSpec{
			Request: request,
			Usages:  []v1beta1.KeyUsage{v1beta1.UsageKeyEncipherment, v1beta1.UsageDigitalSignature},
		},
	}

	kcsr, errcsr := csrClient.Create(csr)

	if errcsr != nil {
		log.Fatal(errcsr)
	}

	kcsr.Status.Conditions = append(kcsr.Status.Conditions, v1beta1.CertificateSigningRequestCondition{Type: v1beta1.CertificateApproved})
	csrClient.UpdateApproval(kcsr)

	resultCsr, _ := csrClient.Get(user, metav1.GetOptions{})
	return resultCsr
}

func createKubeConfig(user, namespace string, privateKey, certificateAuthorityData, certificate []byte) string {

	newconfig := api.NewConfig()
	newconfig.Kind = "Config"
	newconfig.APIVersion = "v1"

	newconfig.Clusters[user] = &api.Cluster{
		Server:                   "https://x.x.x.x:6443",
		InsecureSkipTLSVerify:    false,
		CertificateAuthorityData: certificateAuthorityData,
	}

	newcontextName := fmt.Sprintf("%s-%s", user, "context")

	newconfig.Contexts[newcontextName] = &api.Context{
		Cluster:   user,
		AuthInfo:  user,
		Namespace: namespace,
	}

	newconfig.AuthInfos[user] = &api.AuthInfo{
		ClientKeyData:         privateKey,
		ClientCertificateData: certificate,
	}

	newconfig.CurrentContext = newcontextName

	// serConfigJson, _ := json.Marshal(newconfig)
	// serConfig, _ := yaml.JSONToYAML(serConfigJson)
	// print(string(serConfig))

	// f, _ := os.Create("/tmp/kube.config")
	// defer f.Close()

	// w := bufio.NewWriter(f)
	// w.WriteString(string(serConfig))
	// w.Flush()

	file, _ := ioutil.TempFile(os.TempDir(), "kubeconfig")
	defer os.Remove(file.Name())

	fmt.Printf("temp file is %s\n", file.Name())

	kubeconfig.WriteConfig(newconfig, file.Name())
	content, _ := ioutil.ReadFile(file.Name())
	return string(content)
}

// func createKubeConfigV2(user, namespace string, privateKey, certificateAuthorityData, certificate []byte) {
// 	kubeconfig.KubectlConfig{
// 		Kind:           "Config",
// 		ApiVersion:     "v1",
// 		CurrentContext: fmt.Sprintf("%s-%s", user, "context"),
// 		Clusters: []kubeconfig.KubectlClusterWithName{
// 			kubeconfig.KubectlClusterWithName{
// 				Name:    "kubernetes",
// 				Cluster: kubeconfig.KubectlCluster{
// 					Server: "https://35.230.27.214:6443",
// 					CertificateAuthorityData: certificateAuthorityData,
// 				},
// 			},
// 		},
// 		Contexts: []kubeconfig.KubectlContextWithName{
// 			kubeconfig.KubectlContextWithName{
// 				Name: fmt.Sprintf("%s-%s", user, "context"),
// 				Context: kubeconfig.KubectlContext{
// 					Cluster: "kubernetes",
// 					User: user,
// 				},
// 			},
// 		},
// 		Users: []kubeconfig.KubectlUserWithName{
// 			kubeconfig.KubectlUserWithName{
// 				Name: user,
// 				User: kubeconfig.KubectlUser{
// 					ClientCertificateData: certificate,
// 					ClientKeyData: privateKey,
// 				},
// 			},
// 		}
// 	}
// }

func createNamespace(clientset *kubernetes.Clientset, name string) {
	namespaceSpec := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
	_, err := clientset.CoreV1().Namespaces().Create(namespaceSpec)

	if err != nil {
		log.Fatal(err)
	}
}

func listNodes(clientset *kubernetes.Clientset) []v1.Node {
	nodes, _ := clientset.CoreV1().Nodes().List(metav1.ListOptions{})

	for j, node := range nodes.Items {
		fmt.Printf("[%d] %s\n", j, node.ObjectMeta.Name)
	}

	return nodes.Items
}

func listPods(clientset *kubernetes.Clientset) []v1.Pod {
	pods, _ := clientset.CoreV1().Pods("default").List(metav1.ListOptions{})

	for i, pod := range pods.Items {
		fmt.Printf("[%d] %s\n", i, pod.GetName())
	}

	return pods.Items
}

func pemEncodeData(data []byte) (result string) {
	block := &pem.Block{
		Bytes: data,
	}

	dataWithBanner := pem.EncodeToMemory(block)
	sansBegin := strings.Replace(string(dataWithBanner), "-----BEGIN -----\n", "", -1)
	result = strings.Replace(sansBegin, "\n-----END -----\n", "", -1)
	return
}

func orchestrate(namespace string) string {
	// fmt.Println("Hello world")
	// user := "hello10"
	// namespace := "hello10"

	user := namespace

	kubeconfig := filepath.Join(
		os.Getenv("HOME"), ".kube", "config",
	)

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatal(err)
	}

	request, key := genCsr(namespace, user)
	resultCsr := createCertificate(user, namespace, request, clientset)
	return createKubeConfig(user, namespace, key, config.TLSClientConfig.CAData, resultCsr.Status.Certificate)

	// listPods(clientset)
	// listNodes(clientset)
	// clientset.CoreV1().Nodes().List(metav1.ListOptions{})

}

type RegisterSpec struct {
	ASV string `json:"asv, omitempty"`
	ENV string `json:"env"`
	BAP string `json:"bap, omitempty"`
}

func Register(w http.ResponseWriter, r *http.Request) {
	// params := mux.Vars(r)
	var registerSpec RegisterSpec
	json.NewDecoder(r.Body).Decode(&registerSpec)

	data, _ := json.Marshal(registerSpec)
	fmt.Println(string(data))

	result := orchestrate(registerSpec.ENV)

	json.NewEncoder(w).Encode(result)
}

func main() {
	router := mux.NewRouter()
	router.HandleFunc("/system/register", Register).Methods("POST")
	log.Fatal(http.ListenAndServe(":8000", router))
}
