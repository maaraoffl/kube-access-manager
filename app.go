package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/cloudflare/cfssl/csr"
	"k8s.io/api/certificates/v1beta1"
	"k8s.io/api/core/v1"

	"encoding/json"
	"encoding/pem"

	"github.com/ghodss/yaml"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

var clusterName string

func init() {
	clusterName = os.Getenv("CLUSTER_NAME")
}

func genCsr(namespace string, username string) (string, string) {

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

	csr, keys, _ := csr.ParseRequest(&csrq)
	// fmt.Println(string(csr[:]))
	// fmt.Println(string(keys[:]))
	return string(csr[:]), string(keys[:])
}

// func kcreateCertificate() {

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

func main() {
	// fmt.Println("Hello world")
	user := "hello10"
	namespace := "hello10"

	kubeconfig := filepath.Join(
		os.Getenv("HOME"), ".kube", "config",
	)

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatal(err)
	}

	// bdata, _ := json.Marshal(config.TLSClientConfig)
	// fmt.Println(string(bdata[:]))

	fmt.Println("---------------------------------")

	request, key := genCsr(namespace, user)
	// encodedRequest :=[]byte(base64.StdEncoding.EncodeToString([]byte(request)))

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
			Request: []byte(request),
			Usages:  []v1beta1.KeyUsage{v1beta1.UsageKeyEncipherment, v1beta1.UsageDigitalSignature},
		},
	}

	kcsr, errcsr := csrClient.Create(csr)

	if errcsr != nil {
		log.Fatal(errcsr)
	}

	kcsr.Status.Conditions = append(kcsr.Status.Conditions, v1beta1.CertificateSigningRequestCondition{Type: v1beta1.CertificateApproved})

	// certCsr, _ :=
	csrClient.UpdateApproval(kcsr)
	// fmt.Println(certCsr.Status)
	// fmt.Println(string(key[:]))

	resultCsr, _ := csrClient.Get(user, metav1.GetOptions{})
	// block := &pem.Block{Bytes: resultCsr.Status.Certificate}

	// certificate := pemEncodeData(resultCsr.Status.Certificate)

	newconfig := api.NewConfig()
	newconfig.Kind = "Config"
	newconfig.APIVersion = "v1"

	newconfig.Clusters[user] = &api.Cluster{
		Server:                   "https://35.230.27.214:6443",
		InsecureSkipTLSVerify:    false,
		CertificateAuthorityData: config.TLSClientConfig.CAData,
	}

	newcontextName := fmt.Sprintf("%s-%s", user, "context")

	newconfig.Contexts[newcontextName] = &api.Context{
		Cluster:   user,
		AuthInfo:  user,
		Namespace: namespace,
	}

	newconfig.AuthInfos[user] = &api.AuthInfo{
		ClientKeyData:         []byte(key),
		ClientCertificateData: []byte(resultCsr.Status.Certificate),
	}

	newconfig.CurrentContext = newcontextName

	serConfigJson, _ := json.Marshal(newconfig)
	serConfig, _ := yaml.JSONToYAML(serConfigJson)
	print(string(serConfig))

	f, _ := os.Create("/tmp/kube.config")
	defer f.Close()

	w := bufio.NewWriter(f)
	w.WriteString(string(serConfig))
	w.Flush()

	// fmt.Println(time.Now())
	// listPods(clientset)
	// listNodes(clientset)

	// clientset.CoreV1().Nodes().List(metav1.ListOptions{})

}
