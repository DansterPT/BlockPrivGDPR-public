/*
Copyright 2021 IBM All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"bytes"
	"sync/atomic"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"io/ioutil"
	"path"
	"crypto/rand"
	"math/big"
	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"github.com/hyperledger/fabric-protos-go-apiv2/gateway"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)
//--logging--
type counter struct {
    n int32
}

func (c *counter) Add() {
    atomic.AddInt32(&c.n, 1)
}

func (c *counter) AddArb(v int32) {
    atomic.AddInt32(&c.n, v)
}

func (c *counter) Sub() {
    atomic.AddInt32(&c.n, -1)
}

func (c *counter) Reset() {
    atomic.StoreInt32(&c.n, 0)
}

func (c *counter) Get() int {
    return int(atomic.LoadInt32(&c.n))
}
var c2 counter
var c3 counter
//-- 


const (
	mspID         = "Org1MSP"
	cryptoPath    = "/home/ubuntu/go/src/github.com/ubuntu/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com"
	certPath      = cryptoPath + "/users/User1@org1.example.com/msp/signcerts/cert.pem"
	keyPath       = cryptoPath + "/users/User1@org1.example.com/msp/keystore/"
	tlsCertPath   = cryptoPath + "/peers/peer0.org1.example.com/tls/ca.crt"
	peerEndpoint  = "localhost:7051"
	gatewayPeer   = "peer0.org1.example.com"
	channelName   = "mychannel"
	chaincodeName = "basic"
)

//ID for JCA invoke 
type assetJCA struct {
	ID             string 	`json:"ID"`
}

type AssetPrivateDetails struct {
	ID             string `json:"ID"`
	Name	       string `json:"name"`
	Email	       string `json:"email"`
	Salt	       string `json:"salt"`
	SCounter       	int	`json:"sCounter"`
	SSum		int	`json:"sSum"`
}


// newGrpcConnection creates a gRPC connection to the Gateway server.
func newGrpcConnection() *grpc.ClientConn {
	certificate, err := loadCertificate(tlsCertPath)
	if err != nil {
		panic(err)
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(certificate)
	transportCredentials := credentials.NewClientTLSFromCert(certPool, gatewayPeer)

	connection, err := grpc.Dial(peerEndpoint, grpc.WithTransportCredentials(transportCredentials))
	if err != nil {
		panic(fmt.Errorf("failed to create gRPC connection: %w", err))
	}

	return connection
}

// newIdentity creates a client identity for this Gateway connection using an X.509 certificate.
func newIdentity() *identity.X509Identity {
	certificate, err := loadCertificate(certPath)
	if err != nil {
		panic(err)
	}

	id, err := identity.NewX509Identity(mspID, certificate)
	if err != nil {
		panic(err)
	}

	return id
}

func loadCertificate(filename string) (*x509.Certificate, error) {
	certificatePEM, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}
	return identity.CertificateFromPEM(certificatePEM)
}

// newSign creates a function that generates a digital signature from a message digest using a private key.
func newSign() identity.Sign {
	files, err := ioutil.ReadDir(keyPath)
	if err != nil {
		panic(fmt.Errorf("failed to read private key directory: %w", err))
	}
	privateKeyPEM, err := ioutil.ReadFile(path.Join(keyPath, files[0].Name()))

	if err != nil {
		panic(fmt.Errorf("failed to read private key file: %w", err))
	}

	privateKey, err := identity.PrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		panic(err)
	}

	sign, err := identity.NewPrivateKeySign(privateKey)
	if err != nil {
		panic(err)
	}

	return sign
}

func genSaltAT() string{
	const letters ="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	ret:=make([]byte, 64)
	for i:=0; i<64; i++ {
		num, e := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if e != nil {
			fmt.Print(e)
		}
		ret[i] = letters[num.Int64()]	
	}
	return string(ret)
}

func getAssetJCAAsJson() []byte {
	//c2.Add() //increments counter
	asset3 := assetJCA{
		ID : strconv.Itoa(c2.Get()),
	}
	
	jsonStr, err1 := json.Marshal(asset3)
	if err1 != nil {
		fmt.Printf("Error: %s", err1.Error())
	}

	return jsonStr
}


// Submit a transaction synchronously, blocking until it has been committed to the ledger.
/*func createAssetConsent(contract *client.Contract, assetId string, consentFlag string) {
	fmt.Printf("Submit Transaction: CreateAssetConsent, creates new asset consent with ID, consentFlag arguments \n")

	_, err := contract.SubmitTransaction("CreateAssetConsent", assetId, consentFlag)
	if err != nil {
		//panic(fmt.Errorf("failed to submit transaction: %w", err))
		fmt.Printf("failed to submit transaction: %w", err)
		exampleErrorHandling(err)
		return
	}

	fmt.Printf("*** Transaction committed successfully\n")
}*/

func createAssetConsent(contract *client.Contract, assetId string, consentFlag string) string {
	fmt.Printf("Submit Transaction: CreateAssetConsent, creates new asset consent with ID, consentFlag arguments \n")
	
	asset_JCA := map[string][]byte{
		"JCA_properties" : []byte(getAssetJCAAsJson()), //Now sends also JCAAsset (ID for logging)
	}

	_, err := contract.Submit("CreateAssetConsent", client.WithArguments(assetId, consentFlag), client.WithTransient(asset_JCA), client.WithEndorsingOrganizations("Org1MSP"))
	if err != nil {
		//panic(fmt.Errorf("failed to submit transaction: %w", err))
		fmt.Printf("failed to submit transaction: %w", err)
		exampleErrorHandling(err)
		return "Failure: " + err.Error()
	}

	fmt.Printf("*** Transaction committed successfully\n")
	return "Success"
}


func readAssetConsent(contract *client.Contract, assetId string) string {
	fmt.Printf("Evaluate Transaction: ReadAssetConsent, function returns asset attributes\n")

	evaluateResult, err := contract.EvaluateTransaction("ReadAssetConsent", assetId)
	if err != nil {
		//panic(fmt.Errorf("failed to evaluate transaction: %w", err))
		exampleErrorHandling(err)
		return "Failure: " + err.Error()
	}
	if (len(evaluateResult)!=0){
		result := formatJSON(evaluateResult)
		fmt.Printf("*** Result:%s\n", result)
		return "Success: " + result 
	} else {
		fmt.Printf("*** BAD Result:%s\n", evaluateResult)
		fmt.Printf("*** The asset either doesn't exist, or you don't have permission to access it.\n")
		return "Failure: The asset either doesn't exist, or you don't have permission to access it."
	}
}

func updateAssetConsent(contract *client.Contract, assetId string, consentFlag string, blockedFlag string) string {
	fmt.Printf("Submit Transaction: UpdateAssetConsent, updates an existing asset consent with ID, consentFlag arguments \n")

	_, err := contract.SubmitTransaction("UpdateAssetConsent", assetId, consentFlag, blockedFlag)
	if err != nil {
		//panic(fmt.Errorf("failed to submit transaction: %w", err))
		fmt.Printf("failed to submit transaction: %w", err)
		exampleErrorHandling(err)
		return "Failure: " + err.Error()
	}

	fmt.Printf("*** Transaction committed successfully\n")
	return "Success"
}


func updateAsset(contract *client.Contract, assetId string, rep string) string {
	fmt.Printf("Submit Transaction: UpdateAsset, updates an existing asset consent with ID, rep arguments \n")

	_, err := contract.SubmitTransaction("UpdateAssetScore", assetId, rep)
	if err != nil {
		//panic(fmt.Errorf("failed to submit transaction: %w", err))
		fmt.Printf("failed to submit transaction: %w", err)
		exampleErrorHandling(err)
		return "Failure: " + err.Error()
	}

	fmt.Printf("*** Transaction committed successfully\n")
	return "Success"
}


// Submit a transaction synchronously, blocking until it has been committed to the ledger.
func createAsset(contract *client.Contract, assetId string, rep int, name string, email string) string {
	fmt.Printf("Submit Transaction: CreateAsset, creates new asset consent with ID, Rep, Name, Email, Salt arguments \n")
	
	type assetTransient struct {
		ID             string 	`json:"ID"`
		Rep            int 	`json:"rep"`
		Name           string   `json:"name"`
		Email	       string  	`json:"email"`
		Salt	       string	`json:"salt"`
	}
	saltVal:= genSaltAT()
	asset1 := assetTransient{
		ID : assetId,
		Rep : rep,
		Name : name,
		Email : email,
		Salt : saltVal,
	}
	
	jsonStr, err1 := json.Marshal(asset1)
	if err1 != nil {
        	fmt.Printf("Error: %s", err1.Error())
        	return "Failure: " + err1.Error()
    	}

	asset_properties := map[string][]byte{
		"asset_properties" : []byte(jsonStr),
		"JCA_properties" : []byte(getAssetJCAAsJson()),//Now sends also JCAAsset (ID for logging)
	}

	_, err := contract.Submit("CreateAsset", client.WithTransient(asset_properties), client.WithEndorsingOrganizations("Org1MSP"))
	if err != nil {
		//panic(fmt.Errorf("failed to submit transaction: %w", err))
		fmt.Printf("failed to submit transaction: %w", err)
		exampleErrorHandling(err)
		return "Failure: " + err.Error()
	}


	/*_, err = txn.Submit()
	if err != nil {
		panic(fmt.Errorf("failed to submit transaction: %w", err))
	}*/


	fmt.Printf("*** Transaction committed successfully\n")
	return "Success"
}

// Submit a transaction synchronously, blocking until it has been committed to the ledger.
func updateAssetPersonal(contract *client.Contract, assetId string, name string, email string) string {
	fmt.Printf("Submit Transaction: UpdateAssetPersonal, updates personal data with ID, Name, Email arguments \n")
	
	type assetTransient struct {
		ID             string 	`json:"ID"`
		Name           string   `json:"name"`
		Email	       string  	`json:"email"`
	}
	asset1 := assetTransient{
		ID : assetId,
		Name : name,
		Email : email,
	}
	
	jsonStr, err1 := json.Marshal(asset1)
	if err1 != nil {
        	fmt.Printf("Error: %s", err1.Error())
        	return "Failure: " + err1.Error()
    	}
	
	asset_properties := map[string][]byte{
		"asset_properties" : []byte(jsonStr),
		"JCA_properties" : []byte(getAssetJCAAsJson()),//Now sends also JCAAsset (ID for logging)
	}

	_, err := contract.Submit("UpdateAssetPersonal", client.WithTransient(asset_properties), client.WithEndorsingOrganizations("Org1MSP"))
	if err != nil {
		//panic(fmt.Errorf("failed to submit transaction: %w", err))
		fmt.Printf("failed to submit transaction: %w", err)
		exampleErrorHandling(err)
		return "Failure: " + err.Error()
	}

	fmt.Printf("*** Transaction committed successfully\n")
	return "Success"
}

func deleteAsset(contract *client.Contract, assetId string) string {
	fmt.Printf("Submit Transaction: DeleteAsset\n")
	
	type assetTransientDelete struct {
		ID             string 	`json:"ID"`
	}
	
	asset1 := assetTransientDelete{
		ID : assetId,
	}
	
	jsonStr, err1 := json.Marshal(asset1)
	if err1 != nil {
        	fmt.Printf("Error: %s", err1.Error())
        	return "Failure: " + err1.Error()
    	}
	//fmt.Printf(string(jsonStr))
	asset_delete := map[string][]byte{
		"asset_delete" : []byte(jsonStr),
	}
	//fmt.Printf(string(asset_delete["asset_delete"]))
	_, err := contract.Submit("DeleteAsset", client.WithTransient(asset_delete))
	if err != nil {
		panic(fmt.Errorf("failed to submit transaction: %w", err))
		return "Failure: " + err.Error()
	}

	fmt.Printf("*** Transaction committed successfully\n")
	return "Success"
}



// Evaluate a transaction by assetID to query ledger state.
func readAsset(contract *client.Contract, assetId string) string{
	fmt.Printf("Evaluate Transaction: ReadAsset, function returns asset attributes\n")

	evaluateResult, err := contract.EvaluateTransaction("ReadAsset", assetId)
	if err != nil {
		//panic(fmt.Errorf("failed to evaluate transaction: %w", err))
		exampleErrorHandling(err)
		return "Failure: " + err.Error()
	}
	if (len(evaluateResult)!=0){
		result := formatJSON(evaluateResult)
		fmt.Printf("*** Result:%s\n", result)
		return "Success: " + result
	} else {
		fmt.Printf("*** BAD Result:%s\n", evaluateResult)
		fmt.Printf("*** The asset either doesn't exist, or you don't have permission to access it.\n")
		return "Failure: The asset either doesn't exist, or you don't have permission to access it."
	}
}

func readAssetPrivateDetails(contract *client.Contract, assetId string) string{
	fmt.Printf("Evaluate Transaction: ReadAssetPrivateDetails, function returns asset attributes\n")

	evaluateResult, err := contract.EvaluateTransaction("ReadAssetPrivateDetails", "Org1MSPPrivateCollection", assetId)
	if err != nil {
		//panic(fmt.Errorf("failed to evaluate transaction: %w", err))
		exampleErrorHandling(err)
		return "Failure: " + err.Error()
	}
	if (len(evaluateResult)!=0){
		var assetPvt AssetPrivateDetails
		err = json.Unmarshal(evaluateResult, &assetPvt)
		if err != nil {
			exampleErrorHandling(err)
			return "Failure: " + err.Error()
		}
		assetPvt.Salt="hiddenForSecurityReasons"
		//result := formatJSON(assetPvt)
		fmt.Printf("*** Result:%s\n", assetPvt)
		jsonStr, err1 := json.Marshal(assetPvt)
		if err1 != nil {
        		fmt.Printf("Error: %s", err1.Error())
        		return "Failure: " + err1.Error()
    		}
		result1 := formatJSON(jsonStr)
		return "Success: " + string(result1)
	} else {
		fmt.Printf("*** BAD Result:%s\n", evaluateResult)
		fmt.Printf("*** The asset either doesn't exist, or you don't have permission to access it.\n")
		return "Failure: The asset either doesn't exist, or you don't have permission to access it."
	}
}

func rightOfAccess (contract *client.Contract, assetId string) string {
	fmt.Printf("Evaluate Transactions: ReadAssetPrivateDetails + ReadAsset, function returns asset attributes\n")
	evaluateResult, err := contract.EvaluateTransaction("ReadAsset", assetId)
	evaluateResult1, err1 := contract.EvaluateTransaction("ReadAssetPrivateDetails", "Org1MSPPrivateCollection", assetId)
	if err != nil {
		exampleErrorHandling(err)
		return "Failure: " + err.Error()
	} else if err1!=nil {
		exampleErrorHandling(err1)
		return "Failure: " + err1.Error()
	}
	
	if (len(evaluateResult)!=0 && len(evaluateResult1)!=0){
		result := formatJSON(evaluateResult)
		var assetPvt AssetPrivateDetails
		err = json.Unmarshal(evaluateResult1, &assetPvt)
		if err != nil {
			exampleErrorHandling(err)
			return "Failure: " + err.Error()
		}
		assetPvt.Salt="hiddenForSecurityReasons"
		jsonStr, err1 := json.Marshal(assetPvt)
		if err1 != nil {
        		fmt.Printf("Error: %s", err1.Error())
        		return "Failure: " + err1.Error()
    		}
		result1 := formatJSON(jsonStr)
		fmt.Println("Success querying data. Here it is:")
		fmt.Println("Restricted data result:%s\n", result)
		fmt.Println("Private data result:%s\n", result1)
		fmt.Println("Purpose of the data: Calculate Reputation Score, based on input from entities who provided services")
		fmt.Println("Restricted data shared with: Org1MSP, Org2MSP. Private data shared with Org1MSP")
		fmt.Println("Storage time: 6 months without interaction and/or until 31/12/2026.")
		fmt.Println("Source of the data: AIoT Environment.")
		fmt.Println("Automated decision making envolved?: No. All processes in the Blockchain are automated, however, there's no decision making.")
		return "Success: " + "Restricted data result: " + result + "\nPrivate data result: " + result1 + "\nPurpose of the data: Calculate Reputation Score, based on input from entities who provided services\n" + "Restricted data shared with: Org1MSP, Org2MSP. Private data shared with Org1MSP\n" + "Storage time: 6 months without interaction and/or until 31/12/2026.\n" + "Source of the data: AIoT Environment.\n" + "Automated decision making envolved?: No. All processes in the Blockchain are automated, however, there's no decision making."
	} else {
		fmt.Printf("*** BAD Result:%s\n", evaluateResult)
		fmt.Printf("*** The asset either doesn't exist, or you don't have permission to access it.\n")
		return "Failure: The asset either doesn't exist, or you don't have permission to access it."
	}
}

func createUnknownAsset(contract *client.Contract, assetId string, unkStr1 string, unkStr2 string, unkPvt1 string, unkPvt2 string, unkPvt3 string) string {
	fmt.Printf("Submit Transaction: CreateUnknownAsset, creates new unknown asset (max 2 restricted, 3 private) \n")
	
	type assetTransient2 struct {
		ID             string 	`json:"ID"`
		UnkPvt1        string 	`json:"unkPvt1"`
		UnkPvt2        string   `json:"unkPvt2"`
		UnkPvt3	       string  	`json:"unkPvt3"`
		Salt	       string	`json:"salt"`
	}
	saltVal:=genSaltAT()
	asset1 := assetTransient2{
		ID : assetId,
		UnkPvt1 : unkPvt1,
		UnkPvt2 : unkPvt2,
		UnkPvt3 : unkPvt3,
		Salt : saltVal,
	}
	
	jsonStr, err1 := json.Marshal(asset1)
	if err1 != nil {
        	fmt.Printf("Error: %s", err1.Error())
        	return "Failure: " + err1.Error()
    	}

	asset_properties := map[string][]byte{
		"unkAsset_properties" : []byte(jsonStr),
		"JCA_properties" : []byte(getAssetJCAAsJson()),//Now sends also JCAAsset (ID for logging)
	}

	_, err := contract.Submit("CreateUnknownAsset", client.WithArguments(assetId, unkStr1, unkStr2), client.WithTransient(asset_properties), client.WithEndorsingOrganizations("Org1MSP"))
	if err != nil {
		//panic(fmt.Errorf("failed to submit transaction: %w", err))
		c3.Add() //Count Nr of Failed attemps
		fmt.Printf("failed to submit transaction: %w", err)
		exampleErrorHandling(err)
		return "Failure: " + err1.Error()
	}


	/*_, err = txn.Submit()
	if err != nil {
		panic(fmt.Errorf("failed to submit transaction: %w", err))
	}*/


	fmt.Printf("*** Transaction committed successfully\n")
	return "Success"
}


func readUnknownAsset(contract *client.Contract, assetId string) string{
	fmt.Printf("Evaluate Transaction: ReadUnknownAsset, function returns asset attributes\n")

	evaluateResult, err := contract.EvaluateTransaction("ReadUnknownAsset", assetId)
	if err != nil {
		//panic(fmt.Errorf("failed to evaluate transaction: %w", err))
		exampleErrorHandling(err)
		return "Failure: " + err.Error()
	}
	if (len(evaluateResult)!=0){
		result := formatJSON(evaluateResult)
		fmt.Printf("*** Result:%s\n", result)
		return "Success: " + result
	} else {
		fmt.Printf("*** BAD Result:%s\n", evaluateResult)
		fmt.Printf("*** The asset either doesn't exist, or you don't have permission to access it.\n")
		return "Failure: The asset either doesn't exist, or you don't have permission to access it."
	}
}

func readUnknownAssetPrivateDetails(contract *client.Contract, assetId string) string{

	type assetTransient2 struct {
		ID             string 	`json:"ID"`
		UnkPvt1        string 	`json:"unkPvt1"`
		UnkPvt2        string   `json:"unkPvt2"`
		UnkPvt3	       string  	`json:"unkPvt3"`
		Salt	       string	`json:"salt"`
	}	
	
	fmt.Printf("Evaluate Transaction: ReadUnknownAssetPrivateDetails, function returns asset attributes\n")

	evaluateResult, err := contract.EvaluateTransaction("ReadUnknownAssetPrivateDetails", "Org1MSPPrivateCollection", assetId)
	if err != nil {
		//panic(fmt.Errorf("failed to evaluate transaction: %w", err))
		exampleErrorHandling(err)
		return "Failure: " + err.Error()
	}
	if (len(evaluateResult)!=0){
		var assetPvt assetTransient2
		err = json.Unmarshal(evaluateResult, &assetPvt)
		if err != nil {
			exampleErrorHandling(err)
			return "Failure: " + err.Error()
		}
		assetPvt.Salt="hiddenForSecurityReasons"
		jsonStr, err1 := json.Marshal(assetPvt)
		if err1 != nil {
        		fmt.Printf("Error: %s", err1.Error())
        		return "Failure: " + err1.Error()
    		}
		result1 := formatJSON(jsonStr)
		fmt.Printf("*** Result:%s\n", result1)
		return "Success: " + result1
	} else {
		fmt.Printf("*** BAD Result:%s\n", evaluateResult)
		fmt.Printf("*** The asset either doesn't exist, or you don't have permission to access it.\n")
		return "Failure: The asset either doesn't exist, or you don't have permission to access it."
	}
}




// Submit transaction, passing in the wrong number of arguments ,expected to throw an error containing details of any error responses from the smart contract.
func exampleErrorHandling(err error) {
	//fmt.Println("Submit Transaction: UpdateAsset asset70, asset70 does not exist and should return an error")

	//_, err := contract.SubmitTransaction("UpdateAsset")
	if err != nil {
		switch err := err.(type) {
		case *client.EndorseError:
			fmt.Printf("Endorse error with gRPC status %v: %s\n", status.Code(err), err)
		case *client.SubmitError:
			fmt.Printf("Submit error with gRPC status %v: %s\n", status.Code(err), err)
		case *client.CommitStatusError:
			if errors.Is(err, context.DeadlineExceeded) {
				fmt.Printf("Timeout waiting for transaction %s commit status: %s", err.TransactionID, err)
			} else {
				fmt.Printf("Error obtaining commit status with gRPC status %v: %s\n", status.Code(err), err)
			}
		case *client.CommitError:
			fmt.Printf("Transaction %s failed to commit with status %d: %s\n", err.TransactionID, int32(err.Code), err)
		}

		// Any error that originates from a peer or orderer node external to the gateway will have its details
		// embedded within the gRPC status error. The following code shows how to extract that.
		statusErr := status.Convert(err)
		for _, detail := range statusErr.Details() {
			switch detail := detail.(type) {
			case *gateway.ErrorDetail:
				fmt.Printf("Error from endpoint: %s, mspId: %s, message: %s\n", detail.Address, detail.MspId, detail.Message)
			}
		}
	}
}

// Format JSON data
func formatJSON(data []byte) string {
	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, data, " ", ""); err != nil {
		panic(fmt.Errorf("failed to parse JSON: %w", err))
	}
	return prettyJSON.String()
}

func main() {
	fmt.Println("Needs GW-receiver to properly work.")
}
