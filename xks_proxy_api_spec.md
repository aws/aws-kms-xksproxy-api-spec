<!---
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: CC-BY-SA-4.0
-->
# Table of Contents

- [External Key Store Proxy API Specification](#external-key-store-proxy-api-specification)
    - [Background](#background)
    - [High level architecture](#high-level-architecture)
    - [API content type](#api-content-type)
    - [API operations](#api-operations)
        - [GetKeyMetadata](#getkeymetadata)
        - [Encrypt](#encrypt)
        - [Decrypt](#decrypt)
        - [GetHealthStatus](#gethealthstatus)
    - [Error codes](#error-codes)
    - [Authentication](#authentication)
        - [SigV4 Credentials Rotation](#sigv4-credentials-rotation)
    - [Authorization](#authorization)
    - [Logging](#logging)
    - [Testing](#testing)
    - [Other considerations](#other-considerations)
        - [Load balancer health checks](#load-balancer-health-checks)
        - [XKS proxy configuration in AWS KMS console](#xks-proxy-configuration-in-aws-kms-console)
        - [Troubleshooting](#troubleshooting)
    - [Appendix A: Using SigV4 to sign XKS proxy requests](#appendix-a-using-sigv4-to-sign-xks-proxy-requests)
        - [Task 1: Create a canonical request](#task-1-create-a-canonical-request)
        - [Task 2: Create a string to sign](#task-2-create-a-string-to-sign)
        - [Task 3: Calculate the signature](#task-3-calculate-the-signature)
        - [Task 4: Match the signature](#task-4-match-the-signature)
    - [Appendix B: RequestMetadata fields](#appendix-b-requestmetadata-fields)
    - [Appendix C: Ciphertext Data Integrity Value (CDIV) implementation guidelines](#appendix-c-ciphertext-data-integrity-value-cdiv-implementation-guidelines)
    - [Appendix D: Using curl for XKS API calls](#appendix-d-using-curl-for-xks-api-calls)
    - [Appendix E: Change log](#appendix-e-change-log)




<div style="page-break-after: always"/>


# External Key Store Proxy API Specification

*Last Updated: Nov 10, 2022*

See [Appendix E](#appendix-e-change-log) for a history of the changes.


## Background

**External Key Stores** is a new capability in AWS Key Management Service (AWS KMS) that allows customers to protect their data in AWS using cryptographic keys held inside on-premises Hardware Security Modules (HSMs) or other key managers outside of AWS. This integration mimics existing support for AWS CloudHSM within KMS except that the customer-controlled HSM resides outside of an AWS data center. This document uses the term *external key manager* to cover both external HSMs and external software-only key managers (aka virtual HSMs).

AWS services typically do not use a KMS key directly for encrypting customer data. Instead, they generate data keys and use envelope encryption to protect customer data. The data keys are encrypted using a KMS key and kept next to the data they encrypt. The plaintext version of  the data key is held in-memory by the integrated service only for a short period. Attempts to access encrypted customer data result in a decrypt API call to KMS to get the plaintext data key. When the key material for a KMS key is hosted in external key managers, cryptographic operations to unwrap/wrap the data key are performed in a customer-chosen datacenter outside AWS.

The new capability is meant to support a variety of external key managers from different vendors. The architecture introduces a proxy, the External Key Story Proxy (aka XKS Proxy), whose primary purpose is to abstract away the API differences across various types of external key managers. The XKS Proxy presents KMS with a uniform API interface described in this document. KMS maintains a fleet of hosts, the XKS Proxy Management Fleet, that communicates with multiple instances of XKS Proxies. The rest of this document describes Version 1 of the XKS Proxy interface including message formats,  authentication and authorization controls, error conditions and additional implementation guidance. 

KMS keys whose key material resides in an external key manager can be distinguished from other KMS keys by their *Origin* which is set to **EXTERNAL_KEY_STORE**. 

**Requirements Terminology**
   
The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119)

<div style="page-break-after: always"/>

## High level architecture


![High-level XKS Architecture](XKS_arch_v7.png)
**Figure 1**: High-level KMS architecture with its main components for External Key Store (XKS) support.

Figure 1 shows the high-level architecture for external key store support in AWS KMS. The XKS Proxy abstracts away API differences across multiple types of external key managers and provides a uniform HTTPS-based API for invoking cryptographic operations involving external keys. This standardized interface is indicated by the thick, vertical, dashed lines in Figure 1. Everything to the right of the interface is the customer’s responsibility, everything to the left and inside the AWS boundary is the responsibility of AWS. 

Each type of key manager will require a corresponding XKS Proxy but a single XKS Proxy instance can serve a cluster of key managers.

We support two connectivity options for the communication between KMS and the XKS Proxy: 

1. XKS Proxy as a [VPC Endpoint Service](https://docs.aws.amazon.com/vpc/latest/privatelink/endpoint-service-overview.html) in the Customer’s Amazon VPC: With this option, customers can run the XKS Proxy on a private network (i.e. one using RFC 1918 private addresses). The proxy may be located in the customer's data center (as shown for Customer A) or in an Amazon VPC (as shown for Customer B). In each case, customers will need to create an NLB and a VPC endpoint service in their Amazon VPC. The target group associated with the NLB will use private IP addresses associated with the XKS proxy. Customers will also need to connect their Amazon VPC to their on-premises data center using any of the available mechanisms such as a VPN or Direct Connect. 
2. XKS Proxy as a public endpoint: Customers can choose to make the proxy available as a publicly routable endpoint (as shown for Customer C) in their data center. This is the simpler connectivity option but it will experience greater variance in network performance since all traffic is going over the Internet. Request authentication restricts access to the proxy. Customers might choose this option when they are evaluating the external key store feature and switch to the VPC endpoint service connectivity option for production use. 

The following is a brief description of the main entities/components referenced in Figure 1:

* AWS Customer: Calls KMS APIs either directly or via another AWS service that integrates with KMS, such as S3.
* KMS front-end fleet: Front-end service in KMS responsible for authenticating and authorizing requests, processing API input parameters and assembling the final response for the caller. All requests to AWS KMS arrive at the KMS front-end fleet. Those involving a KMS Key in an external key store (identified by a special value of `EXTERNAL_KEY_STORE` in the Origin metadata field) are routed to the XKS Proxy Management Fleet.
* XKS Proxy Management Fleet: A fleet of hosts inside KMS that manage interaction with external key managers via the XKS Proxies. This fleet bridges any gaps in the response produced by the XKS Proxy and what the KMS front-end fleet expects. For example, we do not expose the proprietary format of the ciphertext blob to the XKS Proxy and instead assemble that blob in this fleet from the individual components (authentication tag, IV and ciphertext) returned by the encrypt API call to an XKS Proxy. 
* XKS Proxy: Customers may wish to connect a large variety of external key managers to AWS KMS each speaking a different API flavor (such as web-based, a vendor specific PKCS11 variant, or KMIP). The main purpose of the XKS proxy is to normalize these differences and present KMS with a uniform API for interacting with external key managers. We’ve identified a small set of four APIs — GetKeyMetadata, Encrypt, Decrypt and GetHealthStatus that can be used as building blocks to implement all of the KMS APIs we wish to support at launch for keys in external key stores. Any key manager can be used with the External Key Store feature in KMS by creating an XKS Proxy that implements the four APIs described in this specification.
* Customer’s HSM/External HSM/External Key Manager: A customer HSM (or HSM cluster) or virtual HSM residing in their data center.

<div style="page-break-after: always"/>

## API content type

All requests and responses between the XKS Proxy Management Fleet and the XKS Proxy MUST be sent as JSON over HTTPS with a Content-Type of  `application/json`. The XKS Proxy MUST support HTTP/1.1 or later and TLS 1.2 or later with at least one of these cipher suites: `TLS_AES_256_GCM_SHA384` (TLS 1.3), `TLS_CHACHA20_POLY1305_SHA256` (TLS 1.3), `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` (TLS 1.2), `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` (TLS 1.2). The XKS proxy MUST be able to fall back to HTTP 1.1.

## API operations

A majority of the AWS services that integrate with KMS do so using 256-bit AES keys. For that reason, Version 1 of the XKS Proxy interface does not support asymmetric keys or symmetric keys with a length other than 256-bits, i.e. only SYMMETRIC_DEFAULT KMS keys are supported in version 1.

The following API operations MUST be supported: 

* GetKeyMetadata: 
                Gets metadata for a key in the external key manager, e.g. its type, usage and status
* Encrypt: 
                Performs an AES-GCM encryption on the specified plaintext
* Decrypt: 
                Performs an AES-GCM decryption on the specified ciphertext
* GetHealthStatus: 
                Checks if the external key manager is reachable and available to perform cryptographic operations. 


The requests and responses for these APIs are sent as JSON objects over HTTPS. Every API request sent from KMS to the XKS Proxy includes meta data that provides additional context for the request, e.g. the AWS Principal making a KMS API call that resulted in the XKS Proxy API call or the KMS key involved in the KMS API. These elements are grouped together in the requestMetadata object within the request body (details below). Information included as part of requestMetadata is helpful for auditing and for implementing optional authorization at the XKS Proxy (see [Authorization](#authorization)). Several of the fields in requestMetadata are AWS Resource Names (ARNs). The XKS Proxy MUST support ARN lengths of up to [2048](https://docs.aws.amazon.com/IAM/latest/APIReference/API_Policy.html) characters.

Since each XKS Proxy API request includes requestMetadata, all requests are sent as HTTP POSTs (not GETs) following the recommendation in [RFC 7231](https://datatracker.ietf.org/doc/html/rfc7231#page-24) which states:


>A payload within a GET request message has no defined semantics; sending a payload body on a GET request might cause some existing  implementations to reject the request.


If the XKS Proxy receives an HTTP GET request at a URI associated with any of these four APIs, it MUST reject the request with a 405 Method Not Allowed error. 

The XKS Proxy API specification does not include any APIs that create or destroy keys in an external key manager, or change the metadata associated with those keys. Before calling the KMS **CreateKey API**, one must already have a key in the external key manager. The CreateKey API call to create a KMS key in an external key manager does not create key material in an external key manager, it only establishes an association between a “shell” key in KMS and an external key. The identifier of the external key is an input parameter to the CreateKey API and is stored as metadata associated with the KMS key. 

The URIs used in the XKS Proxy API calls start with something that looks like

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<font size="1">https://\<server>[/\<optional-path-prefix>]/kms/xks/v1</font>

where the parts within angle brackets will vary. Portions of the URL shown within square brackets are optional. This URI prefix is configured into KMS as part of the `CreateCustomKeyStore` API when a customer sets up an external key manager for use with KMS. The part `https://<server>` is specified directly via the `XksProxyUriEndpoint` parameter and the `XksProxyUriPath` parameter specifies `[/<optional-path-prefix>]/kms/xks/v1`.  The total length of the `XksProxyUriPath` MUST NOT exceed 128 characters and MUST NOT include any characters other than a through z, A through Z, 0 through 9, slash (/), dash (-) and underscore (\_). The `<optional-path-prefix>` provides a mechanism to support multiple isolated customers on the same XKS proxy. An XKS proxy MAY implement independent request quotas on each path prefix and respond with a ThrottlingException (see [Error Codes](#error-codes)) if that quota is exceeded.

The XKS APIs involving an external key (encrypt, decrypt, getKeyMetadata) use URIs of the form

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<font size="1">https://\<server>[/\<optional-path-prefix>]/kms/xks/v1/keys/\<externalKeyId>/\<operationIndicator></font>

The **`<server>`** MUST be a fully qualified domain name (rather than an IP address) and the total URI length MUST NOT exceed 256 characters. The **`externalKeyId`** identifies a key in the external key manager and must be unique within the scope of an XKS Proxy endpoint. Each KMS key must be associated with a different external key, i.e. two different KMS keys created in the same external key store (identified by the XKS Proxy endpoint) MUST NOT have the same **`externalKeyId`**. If you try to create a KMS key with an **`externalKeyId`**  that is already associated with an existing KMS key, the CreateKey request will fail.

The encoding of **`externalKeyId`** is opaque to AWS KMS. The only requirements are: (i) the XKS Proxy MUST be able to identify an external key unambiguously from its **`externalKeyId`**, (ii) the length of an **`externalKeyId`** MUST NOT exceed 128 characters and they MUST be restricted to the following set: uppercase or lowercase letters A through Z, the digits 0 through 9, the hyphen, the period and the underscore.


<div style="page-break-after: always"/>

### GetKeyMetadata

This API fetches metadata associated with the external key including its type, supported cryptographic operations and status.

**HTTP Method:** POST

**URI:**  <font size="1">https://\<server>[/\<path-prefix>]/kms/xks/v1/keys/\<externalKeyId>/metadata</font>

**Request Payload Parameters:**
The HTTP body of the request contains requestMetadata fields that provide additional context on the request being made. This information is helpful for auditing and for implementing an optional secondary layer of authorization at the XKS Proxy (see a later section on [Authorization](#authorization)). There is no expectation for the XKS Proxy to validate any information included in the requestMetadata beyond validating the signature that covers the entire request payload. 

1. **requestMetadata** - Nested structure which contains request metadata.
    1. **awsPrincipalArn** - This is the ARN of the principal that invoked KMS CreateKey or DescribeKey (see [aws:PrincipalArn](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-principalarn)). When the caller is another AWS service, this field will contain either the service principal ending in amazonaws.com, such as [ec2.amazonaws.com](http://ec2.amazonaws.com/) or “AWS Internal”. This field is REQUIRED.
    2. **awsSourceVpc** - This field is OPTIONAL. It is present if and only if the KMS API request was made against a VPC endpoint. When present, this field indicates the VPC where the request originated (see [aws:SourceVpc](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-sourcevpc)).
        1. **awsSourceVpce** - This field is OPTIONAL. It is present if and only if the KMS API request was made against a VPC endpoint. When present, this field indicates the VPC endpoint where the request was made (see [aws:SourceVpce](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-sourcevpce))
    3. **kmsKeyArn** - This is the ARN of the KMS Key on which the CreateKey or DescribeKey API was invoked. This field is OPTIONAL. KMS will include this field in the GetKeyMetadata API call if the kmsOperation is DescribeKey but not if the kmsOperation is CreateKey since the keyArn is created after KMS validates the external key. 
    4. **kmsOperation** - This is the KMS API call that resulted in the XKS Proxy API request, e.g. both CreateKey and DescribeKey can result in a GetKeyMetadata call. This field is REQUIRED. The XKS Proxy MUST NOT reject a request as invalid if it sees a kmsOperation other than those listed for this API call. In the future, KMS may introduce a new API (BulkDescribeKey, say) that can be satisfied by calling one of the XKS APIs listed in this document. For proxies that implement [secondary authorization](#authorization), it is acceptable for XKS API requests made as part of the new KMS API to fail authorization. It is easier for a customer to update their XKS Proxy authorization policy than to update their XKS Proxy software. 
    5. **kmsRequestId** - This is the requestId of the call made to KMS which is visible in AWS CloudTrail. The XKS proxy SHOULD log this field to allow a customer to correlate AWS CloudTrail entries with log entries in the XKS Proxy. This field typically follows the format for [UUID](https://en.wikipedia.org/wiki/Universally_unique_identifier)s but the XKS Proxy MUST treat this as an opaque string and MUST NOT perform any validation on its structure. This field is REQUIRED.
    6. **kmsViaService** - This field is OPTIONAL. This field is present if and only if an AWS Service called the KMS API on behalf of a customer see [kms:ViaService](https://docs.aws.amazon.com/kms/latest/developerguide/policy-conditions.html#conditions-kms-via-service)).

        **NOTE**: The kmsKeyArn includes the Region in which the KMS request was made and the account that owns the resource. The awsPrincipalArn includes the account of the caller. The XKS Proxy can also use the Region and account (both key owner and caller) fields in its authorization decision.

<div style="page-break-after: always"/>

**Request Payload Syntax:**

```
{
    "requestMetadata": {
        "awsPrincipalArn": string,
        "awsSourceVpc": string, // optional
        "awsSourceVpce": string, // optional
        "kmsKeyArn": string,
        "kmsOperation": string,
        "kmsRequestId": string,
        "kmsViaService": string // optional     
    }
}
```

**Request Payload Example:**

```
{
    "requestMetadata": {
        "awsPrincipalArn": "arn:aws:iam::123456789012:user/Alice",
        "kmsKeyArn": "arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
        "kmsOperation": "DescribeKey",
        "kmsRequestId": "4112f4d6-db54-4af4-ae30-c55a22a8dfae",
        "kmsViaService": "ebs"      
    }
}
```

**Response Payload Parameters:**
The following attributes MUST be present in response payload:

1. **keySpec** - Specifies the type of external key. This field is REQUIRED. The XKS Proxy must use the string `AES_256` to indicate a 256-bit AES key.
2. **keyUsage** - Specifies an array of cryptographic operations for which external key can be used. This field is REQUIRED. The XKS Proxy must use the strings `ENCRYPT` and `DECRYPT` (all uppercase) to indicate when an external key supports encrypt and decrypt operations, respectively. The XKS Proxy response MAY include additional values supported by that external key, e.g. PKCS11-based HSMs additionally support DERIVE, SIGN, VERIFY, WRAP, UNWRAP. The response MUST NOT contain more than ten keyUsage values.
3. **keyStatus** - Specifies the state of the external key. The supported values are `ENABLED` and `DISABLED`. This field is REQUIRED. If neither the external key manager nor the XKS Proxy support disabling individual keys, the XKS Proxy MUST return ENABLED for this field.


**Success Response Code:** 200 (for errors, see [Error Codes](#error-codes))

**Response Payload Syntax:**

```
{
    "keySpec": string,
    "keyUsage": array of strings,
    "keyStatus": string
}
```

**Response Payload Example:**

```
{
    "keySpec": "AES_256",
    "keyUsage": ["ENCRYPT", "DECRYPT"],
    "keyStatus": "ENABLED"
}
```

<div style="page-break-after: always"/>

**KMS Considerations:**

KMS invokes the XKS Proxy’s GetKeyMetadata API when a customer calls either the KMS CreateKey or DescribeKey API for a KMS key in an external key store. 

Version 1 of this specification only supports creation of AES keys within KMS. When KMS calls GetKeyMetadata as part of a KMS CreateKey call, it will look for specific values in the GetKeyMetadata response. Invocation of the KMS CreateKey API will fail if any one (or more) of the following is true:

* keySpec is not `AES_256` 
* keyUsage is missing `ENCRYPT` or `DECRYPT` (or both)
* keyStatus is not `ENABLED`


When GetKeyMetadata is called as part of a KMS DescribeKey call, the keyStatus and keyUsage fields will be included in the response as part of [key metadata](https://docs.aws.amazon.com/kms/latest/APIReference/API_DescribeKey.html#API_DescribeKey_ResponseSyntax). 

The key state of a KMS key is distinct from the status of the underlying external key and the output of the KMS DescribeKey API includes both pieces of information. Calling the KMS EnableKey or DisableKey API will only change the KMS key state, not the status of the underlying key in the external key manager. The key status in the external key manager MUST be managed by using its native API. 

KMS Encrypt or Decrypt API calls on KMS keys in external key stores will only succeed if the KMS key state is ENABLED and the status of the key in external key manager is also ENABLED. 

If KMS does not receive a response from the XKS proxy for any API call within 250ms, KMS will time out and the corresponding KMS API call will fail. Since the interaction between KMS and an XKS proxy may involve multiple round trips (one each for TCP connection, TLS handshake and HTTP request/response), we recommend placing the external key manager as close as possible to the AWS data center hosting KMS, i.e. the ping latency between the AWS data center and the customer's data center SHOULD be 35ms or less.

<div style="page-break-after: always"/>

### Encrypt

KMS uses this API to encrypt data using a key in an external key manager. 

**HTTP Method:** POST

**URI:**  <font size="1">https://\<server>[/\<path-prefix>]/kms/xks/v1/keys/\<externalKeyId>/encrypt</font>

**Request Payload Parameters:**
The HTTP body of the request contains requestMetadata along with input parameters for the encrypt operation.

1. **requestMetadata** - Nested structure that contains request metadata.
    1. **awsPrincipalArn** - This is the ARN of the principal that invoked KMS Encrypt, GenerateDataKey, GenerateDataKeyWithoutPlaintext or ReEncrypt API. When the caller is another AWS service, this field will contain either the service principal ending in amazonaws.com, such as [ec2.amazonaws.com](http://ec2.amazonaws.com/) or “AWS Internal”. This field is REQUIRED.
    2. **awsSourceVpc** - This field is OPTIONAL. It is present if and only if the KMS API request was made against a VPC endpoint. When present, this field indicates the VPC where the request originated (see [aws:SourceVpc](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-sourcevpc)).
    3. **awsSourceVpce** - This field is OPTIONAL. It is present if and only if the KMS API request was made against a VPC endpoint. When present, this field indicates the VPC endpoint where the request was made (see [aws:SourceVpce](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-sourcevpce))
    4. **kmsKeyArn** - This is the ARN of the KMS Key on which the Encrypt, ReEncrypt, GenerateDataKey or GenerateDataKeyWithoutPlaintext API was invoked. This field is REQUIRED.
    5. **kmsOperation** - This is the KMS API call that resulted in the XKS Proxy API request, e.g. any one of four KMS APIs (Encrypt, ReEncrypt, GenerateDataKey, GenerateDataKeyWithoutPlaintext) can result in an Encrypt call. This field is REQUIRED. The XKS Proxy MUST NOT reject a request as invalid if it sees a kmsOperation other than those listed for this API call. In the future, KMS may introduce a new API (BulkEncrypt, say) that can be satisfied by calling one of the XKS APIs listed in this document. For proxies that implement [secondary authorization](#authorization), it is acceptable for XKS API requests made as part of the new KMS API to fail authorization. It is easier for a customer to update their XKS Proxy authorization policy than to update their XKS Proxy software. 
    6. **kmsRequestId** - This is the requestId of the call made to KMS that is visible in AWS CloudTrail. The XKS proxy SHOULD log this field to allow a customer to correlate AWS CloudTrail entries with log entries in the XKS Proxy. This field typically follows the format for [UUID](https://en.wikipedia.org/wiki/Universally_unique_identifier)s but the XKS Proxy MUST treat this as an opaque string and MUST NOT perform any validation on its structure. This field is REQUIRED.
    7. **kmsViaService** - This field is OPTIONAL. If present, it indicates the AWS service that called the KMS API on behalf of a customer (see [kms:ViaService](https://docs.aws.amazon.com/kms/latest/developerguide/policy-conditions.html#conditions-kms-via-service))
2. **plaintext** - Base64-encoded plaintext provided to external key manager for encryption. The proxy MUST support the ability to process up to 4300 bytes of plaintext data. Note that Base64 encoding of 4300 bytes of binary data will result in a string that is 5737 bytes. Plaintext passed to the encrypt API MUST NOT be logged at XKS Proxy or the external key manager. This field is REQUIRED.
3. **encryptionAlgorithm** - Specifies the algorithm that will be used for encryption. For the `v1` specification, this MUST be `AES_GCM`. This field is REQUIRED. 
4. **additionalAuthenticatedData** (AAD) - AES-GCM is an example of an [AEAD](https://en.wikipedia.org/wiki/Authenticated_encryption) (Authenticated Encryption with Additional Data) cipher for which the encrypt operation produces an authenticationTag in addition to the ciphertext. The authenticationTag can be used to ensure the integrity of the ciphertext and additional data passed as AAD.  For a decrypt call to succeed, the same AAD that was used to create the ciphertext must be supplied to the decrypt operation. This field is OPTIONAL. When present, this field MUST be specified as a Base64 encoded string and used as the Additional Authenticated Data ([AAD](https://docs.aws.amazon.com/crypto/latest/userguide/cryptography-concepts.html#term-aad)) input to the AES-GCM operation inside the external key manager. The XKS Proxy MUST be able to handle AAD values up to 8192 bytes in length (the Base64 encoding of 8192 bytes will be 10925 bytes).
5. **ciphertextDataIntegrityValueAlgorithm** (CDIV Algorithm) - Indicates the hashing algorithm to be used in the
computation of the Ciphertext Data Integrity Value (CDIV). For the first version (v1) of this specification, this MUST be "SHA_256". This field is OPTIONAL. When present, the XKS Proxy MUST return a ciphertextDataIntegrityValue field in its response as described below.

<div style="page-break-after: always"/>

**Request Payload Syntax:**

```
{
    "requestMetadata": {
        "awsPrincipalArn": string,
        "awsSourceVpc": string, // optional
        "awsSourceVpce": string, // optional
        "kmsKeyArn": string,
        "kmsOperation": string,
        "kmsRequestId": string,
        "kmsViaService": string // optional   
    },
    "additionalAuthenticatedData": string (Base64 encoded), // optional
    "plaintext": string (Base64 encoded),
    "encryptionAlgorithm": string,
    "ciphertextDataIntegrityValueAlgorithm": string // optional
}
```

**Request Payload Example:**
In this example, the plaintext is a Base64 encoding of “`Hello World!`” and the additionalAuthenticationData is the Base64 encoding of "`project=nile,department=marketing`"

```
{
    "requestMetadata": {
        "awsPrincipalArn": "arn:aws:iam::123456789012:user/Alice",
        "kmsKeyArn": "arn:aws:kms:us-east-2:123456789012:/key/1234abcd-12ab-34cd-56ef-1234567890ab",
        "kmsOperation": "Encrypt",
        "kmsRequestId": "4112f4d6-db54-4af4-ae30-c55a22a8dfae",
        "kmsViaService": "ebs"
    }, 
    "additionalAuthenticatedData": "cHJvamVjdD1uaWxlLGRlcGFydG1lbnQ9bWFya2V0aW5n",
    "plaintext": "SGVsbG8gV29ybGQh",
    "encryptionAlgorithm": "AES_GCM",
    "ciphertextDataIntegrityValueAlgorithm": "SHA_256"
}
```

**Response Payload Parameters:**
The ciphertext, initializationVector and authenticationTag fields MUST be present in response payload. The
ciphertextDataIntegrityValue field MUST be included whenever the request includes
the ciphertextDataIntegrityValueAlgorithm field.

1. **ciphertext** - Base64 encoded ciphertext generated by the external key manager from provided plaintext. Since `AES_GCM` is a stream cipher, the length of the ciphertext MUST be the same as the length of the plaintext. 
2. **ciphertextMetadata:** The XKS Proxy MAY return up to 20 bytes of ciphertext metadata for internal housekeeping, e.g. an external key manager may implement automatic key rotation and use the extra bytes to encode versioning of the key material. This is an OPTIONAL, vendor-specific field. When present, the size of the field MUST NOT exceed 20 bytes and the value MUST be Base64-encoded (the encoded string will be more than 20 bytes). The XKS Proxy MUST append the  `ciphertextMetadata` to the `additionalAuthenticatedData` before normal AES GCM processing to ensure that integrity protection offered by the `authenticationTag` extends to the `ciphertextMetadata`.
NOTE: It is important to explicitly include the length of `additionalAuthenitcatedData` and the length of the `ciphertextMetadata` to avoid unintended successful decrypts, e.g. when a caller calls encrypt with no `additionalAuthenticatedData`, receives a `ciphertextMetadata` in the response and then calls decrypt passing the `ciphertextMetadata` as `additionalAuthenticatedData` and no `ciphertextMetadata`. The AAD input for the external key manager should be computed as (2-byte length of `additionalAuthenticatedData` in big-endian format || `additionalAuthenticatedData` || 1-byte length of `ciphertextMetadata` || `ciphertextMetadata`) where || represents concatenation of the binary values after Base64 decoding. If the `additionalAuthenticatedData` or `ciphertextMetadata` is not present, the corresponding length MUST be set to zero. If the inclusion of the lengths represents a departure from previously implemented behavior, the XKS proxy SHOULD encode the new behavior in the `ciphertextMetadata` and use the encoding to follow the same behavior during decrypt as was used for the corresponding encrypt. Otherwise, previously generated ciphertext will no longer be decryptable. For example, let's say version A of an XKS proxy concatenated the `ciphertextMetdata` directly to `additionalAuthenticatedData` (without including the lengths) but Version B implements new guidance then there needs to be a mechanism to distinguish whether a decrypt call should use the old way or the new way to create the AAD for the external key manager. If Version B always implements the new behavior then ciphertext created by Version A will no longer be decryptable. The `ciphertextMetadata` is the natural place to encode this difference in how the `authenticationTag` was created.
3. **initializationVector** - Base64 encoded initialization vector generated by the external key manager that was used during encrypt operation. The initialization vector MUST be either 12 bytes (96 bits) or 16 bytes (128 bits)
4. **authenticationTag** - Base64 encoded message authentication code generated by external key manager performing AES-GCM encryption. Authentication tag size MUST be 16 bytes (128 bits). Some key managers append the authentication tag to the ciphertext. In such cases, the XKS proxy MUST separate the two before composing the response.
5. **ciphertextDataIntegrityValue** - This field is a Base64 encoded hash computed over the \
`additionalAuthenticatedData` (if present in the request), `ciphertextMetadata` (if present), \
`initializationVector`, `ciphertext` and `authenticationTag` fields in the response. It MUST be included whenever the request includes the `ciphertextDataIntegrityValueAlgorithm` field. The hashing algorithm used to compute this value MUST be the one specified as the `ciphertextDataIntegrityValueAlgorithm` in the request. KMS will independently calculate the `ciphertextDataIntegrityValue` (CDIV) and return an error to the caller if the computed value does not match the value in the response. KMS interprets a match as assurance from the XKS Proxy that a subsequent decrypt call where the caller passes in the same `additionalAuthenticatedData` (if present, in the encrypt request), `initializationVector`, `ciphertext` and `authenticationTag` values will succeed and return the plaintext that was passed as input to this encrypt API. See [Appendix C](#appendix-c-ciphertext-data-integrity-value-cdiv-implementation-guidelines) for a complete example and specific CDIV implementation guidelines.


**Required Attributes:** ALL except **ciphertextMetadata** and **ciphertextDataIntegrityValue**

**Success Response Code:** 200  (for errors, see [Error Codes](#error-codes))


**Response Payload Syntax:**

```
{
    "ciphertext": string (Base64 encoded),
    "ciphertextMetadata": string (Base64 encoded), // Optional
    "initializationVector": string (Base64 encoded),
    "authenticationTag": string (Base64 encoded),
    "ciphertextDataIntegrityValue": string (Base64 encoded) // Optional
}
```

**Response Payload Example:**

Refer to [Appendix C](#appendix-c-ciphertext-data-integrity-value-cdiv-implementation-guidelines) for the CDIV computation.

```
{
    "authenticationTag": "vBxN2ncH1oEkR8WVXpmyYQ==",
    "ciphertext": "ghxkK1txeDNn3q8Y",
    "ciphertextDataIntegrityValue": "qHA/ImC9h5HsLRXqCyPmWgYx7tzyoTplzILbP0fPXsc=",
    "ciphertextMetadata": "a2V5X3ZlcnNpb249MQ==",
    "initializationVector": "HMrlRw85cAJUd5Ax"
}
```

**KMS Considerations:**

The XKS Proxy’s encrypt API is invoked if a customer calls any of the following KMS APIs on a KMS key in an extrenal key store: Encrypt, GenerateDataKey, GenerateDataKeyWithoutPlaintext, ReEncrypt (when the target key id is a KMS key in an external key store). 

If the size of the ciphertext Metadata exceeds 20 bytes, KMS will reject the response from the XKS Proxy and return an error to the caller of the KMS API.

KMS will embed all of the fields in the XKS Proxy’s encrypt response into the ciphertextBlob it returns to the caller.

If KMS does not receive a response from the XKS proxy for any API call within 250ms, KMS will time out and the corresponding KMS API call will fail.

When a KMS caller requests a data key by calling the GenerateDataKey or GenerateDataKeyWithoutPlaintext API, KMS
generates the data key and invokes the XKS Proxy’s encrypt API to wrap that data key. Any corruption of the 
encrypted data key has the potential to make everything encrypted by that data key unreadable. The CDIV 
provides additional assurance about the correctness of the encrypted data key to a KMS caller before it saves 
the encrypted data key and destroys its plaintext version. For this reason, it is important to follow the 
implementation guidelines described in [Appendix C](#appendix-c-ciphertext-data-integrity-value-cdiv-implementation-guidelines).

<div style="page-break-after: always"/>

### Decrypt

This API is used by KMS to decrypt data using a key which resides within an external key manager. 

**HTTP Method:** POST

**URI:**  <font size="1">https://\<server>[/\<path-prefix>]/kms/xks/v1/keys/\<externalKeyId>/decrypt</font>

**Request Payload Parameters:**
The HTTP body of the request contains requestMetadata along with input parameters for the decrypt operation.

1. **requestMetadata** - Nested structure which contains request metadata.
    1. **awsPrincipalArn** - This is the ARN of the principal that invoked the KMS Decrypt or ReEncrypt API. When the caller is another AWS service, this field will contain either the service principal ending in amazonaws.com, such as [ec2.amazonaws.com](http://ec2.amazonaws.com/) or “AWS Internal”. This field is REQUIRED.
    2. **awsSourceVpc** - This field is OPTIONAL. It is present if and only if the KMS API request was made against a VPC endpoint. When present, this field indicates the VPC where the request originated (see [aws:SourceVpc](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-sourcevpc)).
    3. **awsSourceVpce** - This field is OPTIONAL. It is present if and only if the KMS API request was made against a VPC endpoint. When present, this field indicates the VPC endpoint where the request was made (see [aws:SourceVpce](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-sourcevpce))
    4. **kmsKeyArn** - This is the ARN of the KMS Key on which the Decrypt API was invoked. This field is REQUIRED.
    5. **kmsOperation** - This is the KMS API call (either Decrypt or ReEncrypt) that resulted in the XKS Proxy API request. This field is REQUIRED. In the future, The XKS Proxy MUST NOT reject a request as invalid if it sees a kmsOperation other than those listed for this API call. KMS may introduce a new API (BulkDecrypt, say) that can be satisfied by calling one of the XKS APIs listed in this document. For proxies that implement [secondary authorization](#authorization), it is acceptable for XKS API requests made as part of the new KMS API to fail authorization. It is easier for a customer to update their XKS Proxy authorization policy than to update their XKS Proxy software. 
    6. **kmsRequestId** - This is the requestId of the call made to KMS which is visible in AWS CloudTrail. The XKS proxy SHOULD log this field to allow a customer to correlate AWS CloudTrail entries with log entries in the XKS Proxy. This field typically follows the format for [UUID](https://en.wikipedia.org/wiki/Universally_unique_identifier)s but the XKS Proxy MUST treat this as an opaque string and MUST NOT perform any validation on its structure. This field is REQUIRED.
    7. **kmsViaService** - This field is OPTIONAL. If present, it indicates the AWS service that called the KMS API on behalf of a customer (see [kms:ViaService](https://docs.aws.amazon.com/kms/latest/developerguide/policy-conditions.html#conditions-kms-via-service))
2. **ciphertext** - Base64 encoded ciphertext provided to an external key manager for decryption. At a minimum, the proxy MUST support the ability to process 4300 bytes of ciphertext. Note the Base64 encoded string corresponding to 4300 bytes of binary data will be 5737 bytes long. This field is REQUIRED.
3. **ciphertextMetadata:** Base64 encoded `ciphertextMetadata` that was included with the ciphertext in the output of the encrypt call that produced the ciphertext being decrypted. This is an OPTIONAL, vendor-specific field. When present, the size of the field MUST NOT exceed 20 bytes (before Base64 decoding). The XKS Proxy MUST detect when the `ciphertextMetadata` passed to decrypt has been modified relative to the `ciphertextMetadata` generated during the corresponding encrypt. Appending the `ciphertextMetadata` to the `additionalAuthenticatedData` and using that as the AAD for the external key manager, as described in the Encrypt API, will automatically accomplish this.
4. **encryptionAlgorithm** - Specifies the algorithm that was used for encryption. In `v1` specification, this will always be `AES_GCM`. This field is REQUIRED.
5. **additionalAuthenticatedData** (AAD) - AES-GCM is an example of an [AEAD](https://en.wikipedia.org/wiki/Authenticated_encryption) (Authenticated Encryption with Additional Data) cipher for which the encrypt operation produces an authenticationTag in addition to the ciphertext. The authenticationTag can be used to ensure the integrity of the ciphertext and additional data passed as AAD.  For a decrypt call to succeed, the same AAD that was used to create the ciphertext must be supplied to the decrypt operation. This field is OPTIONAL. When present, this field MUST be specified as a Base64 encoded string and used as the Additional Authenticated Data ([AAD](https://docs.aws.amazon.com/crypto/latest/userguide/cryptography-concepts.html#term-aad)) input to the AES-GCM operation inside the external key manager. The XKS Proxy MUST be able to handle AAD values up to 8192 bytes in length (the Base64 encoding of 8192 bytes will be 10925 bytes).
6. **initializationVector** - Base64 encoded initialization vector generated by the external key manager that was used during encrypt operation. For a decrypt call to succeed, this must be the same IV that was generated when the ciphertext was created. This field is REQUIRED. For `AES_GCM`, the length of the initializationVector MUST be 12 bytes or 16 bytes (the Base64 encoding will have 16 bytes or 24 bytes).
7. **authenticationTag** - Base64 encoded message authentication code. Authentication tag size MUST be 16 bytes (the Base64 encoding will have 24 bytes). For a decrypt call to succeed, this must be the same tag that was generated by the encrypt call when the ciphertext was created. This field is REQUIRED.


**Request Payload Syntax:**

```
{
    "requestMetadata": {
        "awsPrincipalArn": string,
        "awsSourceVpc": string, // optional
        "awsSourceVpce": string, // optional
        "kmsKeyArn": string,
        "kmsOperation": string,
        "kmsRequestId": string,
        "kmsViaService": string // optional 
    },  
    "ciphertext": string (Base64 encoded),
    "ciphertextMetadata": string (Base64 encoded), // optional
    "encryptionAlgorithm": string,
    "additionalAuthenticatedData": string (Base64 encoded), // optional
    "authenticationTag": string (Base64 encoded),
    "initializationVector": string (Base64 encoded)
}
```

**Request Payload Example:**

```
{
    "requestMetadata": { 
        "awsPrincipalArn": "arn:aws:iam::123456789012:user/Alice",
        "kmsKeyArn": "arn:aws:kms:us-east-2:123456789012:/key/1234abcd-12ab-34cd-56ef-1234567890ab",
        "kmsOperation": "Decrypt",
        "kmsRequestId": "5112f4d6-db54-4af4-ae30-c55a22a8dfae",
        "kmsViaService": "ebs"
    },
    "additionalAuthenticatedData": "cHJvamVjdD1uaWxlLGRlcGFydG1lbnQ9bWFya2V0aW5n",
    "encryptionAlgorithm": "AES_GCM",
    "ciphertext": "ghxkK1txeDNn3q8Y",
    "ciphertextMetadata": "a2V5X3ZlcnNpb249MQ=="
    "initializationVector": "HMrlRw85cAJUd5Ax",
    "authenticationTag": "vBxN2ncH1oEkR8WVXpmyYQ=="
}
```

**Response Payload Parameters:**

The following attributes MUST be present in request payload:

1. **plaintext** - Base64 encoded plaintext generated by an external key manager from decrypting the provided ciphertext. The size of the plaintext MUST be the same as the size of the ciphertext. Plaintext returned by the decrypt API MUST NOT be logged at XKS Proxy or the external key manager.


**Required Attributes:** ALL

**Success Response Code:** 200  (for errors, see [Error Codes](#error-codes))

**Response Payload Syntax:**

```
{
    "plaintext": string (Base64 encoded)
}
```

**Response Payload Example:**

```
{
    "plaintext": "SGVsbG8gV29ybGQh"
}
```

**KMS Considerations:** 

The XKS Proxy’s decrypt API is invoked if a customer calls any of the following KMS APIs on a KMS key in an extrenal key store: Decrypt, ReEncrypt (when the source key id is a KMS key in an external key store).

KMS will parse the ciphertextblob passed as input to the KMS API to extract the ciphertext, (optional) `ciphertextMetadata`, `initializationVector` and `authenticationTag` and pass as input to the XKS Proxy’s decrypt call.

If KMS does not receive a response from the XKS proxy for any API call within 250ms, KMS will time out and the corresponding KMS API call will fail.

<div style="page-break-after: always"/>

### GetHealthStatus

This API serves multiple purposes

* It is used to ensure that the XKS Proxy base URL (<font size="1">https://\<server>/\<path-prefix>/kms/xks/v1</font>) and SigV4 credentials required to communicate with the proxy are configured correctly in KMS.
* It is used to ensure that the XKS Proxy is ready to handle other API requests (encrypt/decrypt/getKeyMetadata)
* It is used to gather information for proactively monitoring availability risks and processing KMS customer requests to raise the Transactions Per Second (TPS) limit on their external key manager.

Before returning a successful response (HTTP 200 OK), the XKS Proxy SHOULD verify not only that the external key manager is reachable but is also able to perform cryptographic operations, i.e. the health-check SHOULD be deep rather than shallow. The health check should be implemented such that a successful check provides strong assurance that an encrypt, decrypt or getKeyMetadata request issued immediately after will succeed (except due to authorization checks).  The XKS Proxy SHOULD create test keys in the external key manager and invoke cryptographic operations on them as part of the deep Healthcheck. 

This API MUST be excluded from [secondary authorization](#authorization) if the XKS Proxy implements such authorization.

**HTTP Method:** POST

**URI:**  <font size="1">https://\<server>[/\<path-prefix>]/kms/xks/v1/health</font>

**Request Payload Parameters:**
The HTTP body of the request only contains the requestMetadata.

1. **requestMetadata** - Nested structure which contains request metadata.
    1. **kmsRequestId** - This is the requestId of the call made by AWS KMS as part of a periodic health check which is visible in AWS CloudTrail. The XKS proxy SHOULD log this field to allow a customer to correlate AWS CloudTrail entries with log entries in the XKS Proxy. This field typically follows the format for [UUID](https://en.wikipedia.org/wiki/Universally_unique_identifier)s but the XKS Proxy MUST treat this as an opaque string and MUST NOT perform any validation on its structure. This field is REQUIRED. 
    2. **kmsOperation** - This is the KMS API call that resulted in the XKS Proxy API request. This field is REQUIRED. The kmsOperation is set to `CreateCustomKeyStore`, `ConnectCustomKeyStore` or `UpdateCustomKeyStore` when the GetHealthStatus API is called as part of those KMS APIs. This field is set to KmsHealthCheck when GetHealthStatus is called periodically to get health status for publishing to CloudWatch metrics. The XKS Proxy MUST NOT reject a request as invalid if it sees a kmsOperation other than those listed for this API call. 
        
        **NOTE**: AWS KMS does not have a public HealthCheck API. KmsHealthCheck is used only to indicate that the GetHealthStatus XKS API was called by AWS KMS asynchronously from any KMS APIs.

**Request Payload Syntax:**

```
{
    "requestMetadata": {
        "kmsRequestId": string,
        "kmsOperation": string 
    }
}
```

**Request Payload Example:**

```
{
    "requestMetadata": {
        "kmsRequestId": "4112f4d6-db54-4af4-ae30-c55a22a8dfae"
        "kmsOperation": "CreateCustomKeyStore"
    }
}
```

**Response Payload Parameters:**

The following attributes MUST be present in response payload:

1. **xksProxyFleetSize** - Size of XKS proxy fleet. 
2. **xksProxyVendor** - Name of the XKS Proxy vendor, this could be different from the name of the external key manager vendor. Both MUST be included even if they are the same.
3. **xksProxyModel** - Model of the XKS Proxy. This SHOULD include the product name and version.
4. **ekmVendor** - Name of the external key manager vendor.
5. **ekmFleetDetails.id** - Unique identifier for the external key manager in the external key manager cluster.
6. **ekmFleetDetails.model** - Model of the external key manager. This SHOULD include the product name, version of the hardware and any other information that would be useful in troubleshooting and estimating TPS capacity.
7. **ekmFleetDetails.healthStatus** - Status of health check on the external key manager from XKS proxy. The possible statuses are `ACTIVE`, `DEGRADED` and `UNAVAILABLE`. `ACTIVE` means that external key manager is healthy, `DEGRADED` means that external key manager is unhealthy but can still serve traffic and `UNAVAILABLE` means that external key manager is unable to serve traffic.

The response MUST have atleast one and no more than ten entries in ekmFleetDetails.
**Required Parameters:** ALL

**Success Response Code:** 200  (for errors, see [Error Codes](#error-codes))

**Response Payload Syntax:**

```
{
    "xksProxyFleetSize": integer,
    "xksProxyVendor": string,
    "xksProxyModel": string,
    "ekmVendor": string,
    "ekmFleetDetails": [ // array of entries, one per external key manager
        {
            "id": string,
            "model": string,
            "healthStatus": string
        }
        ...
        
    ]
}
```

**Response Payload Example:**

```
{
    "xksProxyFleetSize": 2,
    "xksProxyVendor": "Acme Corp",
    "xksProxyModel": "Acme XKS Proxy 1.0",
    "ekmVendor": "Thales Group",
    "ekmFleetDetails": [
        {
            "id": "hsm-id-1",
            "model": "Luna 5.0",
            "healthStatus": "DEGRADED"
        },
        {
            "id": "hsm-id-2",
            "model": "Luna 5.1",
            "healthStatus": "ACTIVE"
        }
    ]
}
```

<div style="page-break-after: always"/>

**KMS Considerations:**

KMS invokes the GetHealthStatus to validate the XKS Proxy’s endpoint and authentication key when a customer calls the `CreateCustomKeyStore` or `UpdateCustomKeyStore` or `ConnectCustomKeyStore` APIs.

KMS also invokes this API periodically (once every few minutes) asynchronous to any KMS API calls to gather information that is used to determine the health status of the external key manager, potential availability risks (e.g. if the count of external key managers in the cluster drops to one) and its performance capabilities (e.g. if a KMS operator receives a request to raise the Transactions-per-second (TPS) limit for a specific external key manager). The default TPS limit for external key stores is 1800 but customers can request an increase if they can show their XKS Proxy and backing external key manager cluster are appropriately provisioned.

KMS also monitors the latency and availability of all XKS Proxy API calls and publishes them as CloudWatch metrics that are made available in the KMS console on the details page for an external key store. 

If the XKS Proxy invokes an encrypt or decrypt operation in the external key manager as part of this API, it SHOULD do so using a test key in the external key manager rather than a key associated with a KMS key. Otherwise, customers will see periodic cryptographic calls on these keys in the XKS Proxy or external key manager log and they may find it confusing or suspicious to see this activity without corresponding KMS API calls in CloudTrail.

If KMS does not receive a response from the XKS proxy for any API call within 250ms, KMS will time out and the corresponding KMS API call will fail. For some external key managers, performing a deep health check might take longer than 250 ms. For these situations, the XKS Proxy MAY run these health checks periodically on its own (asynchronously with any XKS API calls from KMS) and return a cached result to KMS. The cached result MUST not be older than one minute.

<div style="page-break-after: always"/>

## Error codes

We use standard HTTP error codes but leverage the HTTP body for disambiguation/additional details, e.g. multiple kinds of errors map to HTTP 400. The HTTP body includes a JSON object with `errorName` and an optional `errorMessage`. The table below shows the HTTP error code and Error Name returned by the XKS proxy to signal various error conditions for different APIs. Column 3 indicates the scenario when the corresponding error is returned and column 4 lists the applicable XKS proxy APIs. The `errorMessage`, if included, MUST be less than 512 characters in length and only use printable ASCII characters, i.e. hex values 0x20 (space) through 0x7e (tilde).

<div style="page-break-after: always"/>

| Error Code | Error Name                    | Error Scenario                                                                                                                                                                                                                                                                       | XKS proxy <br>APIs            |
|------------|-------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------|
| 400        | ValidationException           | The request was rejected because one<br>or more input parameters is invalid.                                                                                                                                                                                                         | ALL except<br>GetHealthStatus |
| 400        | InvalidStateException         | The request was rejected because the<br>specified external key or key store is<br>disabled, deactivated or blocked.                                                                                                                                                                      | ALL                           |
| 400        | InvalidCiphertextException    | The request was rejected because the<br>specified ciphertext, initialization vector,<br>additional authenticated data or<br>authentication tag is corrupted, missing,<br>or otherwise invalid.                                                                                       | Decrypt                       |
| 400        | InvalidKeyUsageException      | The request was rejected because the<br>specified key does not support the<br>requested operation.                                                                                                                                                                                   | Decrypt,<br>Encrypt           |
| 401        | AuthenticationFailedException | The request was rejected due to<br>invalid AWS SigV4 signature.                                                                                                                                                                                                                      | ALL                           |
| 403        | AccessDeniedException         | The request was rejected because the<br>operation is not authorized based on<br>request metadata.                                                                                                                                                                                    | ALL except<br>GetHealthStatus |
| 404        | KeyNotFoundException          | The request was rejected because the<br>specified external key is not found.                                                                                                                                                                                                         | ALL except<br>GetHealthStatus |
| 404        | InvalidUriPathException       | The request was rejected because the<br>specified URI path is not valid.                                                                                                                                                                                                             | ALL                           |
| 429        | ThrottlingException           | The request was rejected because the<br>request rate is too high. The<br>proxy may send this either because<br>it is unable to keep up or the caller<br>exceeded its request quota.                                                                                                  | ALL                           |
| 501        | UnsupportedOperationException | The request was rejected because the<br>specified cryptographic operation is not<br>implemented, or if a parameter value<br>exceeded the maximum size that is<br>currently supported by a specific<br>implementation beyond the minimize size<br>required by this API specification. | ALL                           |
| 503        | DependencyTimeoutException    | The XKS proxy timed out while trying to<br>access a dependency layer to fulfill the<br>request.                                                                                                                                                                                      | ALL                           |
| 500        | InternalException             | This is a generic server error. For example,<br>this exception is thrown due to failure of<br>the backing key manager, or failure of a<br>dependency layer.                                                                                                                                  | ALL                           |


<div style="page-break-after: always"/>

**Example:**
The following example illustrates a failure when a decrypt operation is called on an external key with ciphertext that was created using a different value of the additionalAuthenticatedData (AAD) field. The optional `errorMessage` field allows the proxy to provide additional details on the cause of failure.

**HTTP Error Code:** 400 (Bad Request)
**Response Payload Example**: 

```
{
    "errorName": "InvalidCiphertextException", // required
    "errorMessage": "The request was rejected because the specified ciphertext, or additional authenticated data is corrupted, missing, or otherwise invalid." // optional
}
```

**KMS Considerations:**

While the external key store feature introduces new failure scenarios in exisiting KMS APIs, KMS cannot introduce new exceptions without breaking backward compatibility for other AWS services that call KMS. Instead, KMS will use the exception message string to communicate what went wrong and what to do about it. The following table shows the new KMS exception messages introduced by the External Key Store feature and situations when those messages are used.

When the XKS proxy returns a JSON formatted response with `errorName`, KMS will use the `errorName` to determine the exception message as shown. Depending on the KMS API being invoked, the same failure scenario can result in different exceptions but the exception message will be the same. KMS will not include the `errorMessage` returned by the proxy in the error message it returns to a KMS caller. Instead, KMS will log that string in Amazon CloudWatch Logs for the calling account.

If an XKS proxy returns an HTTP error code without a JSON-formatted body or any other type of malformed response, the KMS exception message will be generic and say "AWS KMS cannot interpret the response from the external key store proxy. If you see this error repeatedly, report it to your external key store proxy administrator."

<div style="page-break-after: always"/>


| Failure Scenario                                  | KMS Exception<br>(KMS Operation)                                                                                                                                                                        | KMS Exception<br>Message                                                                                                                                                                                                                                                                                                 |
|---------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Proxy returns a<br>ValidationException            | XksProxyInvalidResponseException<br>(Create/UpdateCustomKeyStore)<br>CustomKeyStoreInvalidStateException<br>(CreateKey)<br>KMSInvalidStateException<br>(Cryptographic operations)                       | AWS KMS cannot interpret the<br>response from the external<br>key store proxy. If you see<br>this error repeatedly, report<br>it to your external key store<br>proxy administrator.                                                                                                                                      |
| Proxy returns an<br>InvalidStateException         | XksKeyInvalidConfigurationException<br>(CreateKey)<br>KMSInvalidStateException<br>(Cryptographic operations)                                                                                            | The external key associated<br>with this KMS key in an<br>external key store is not<br>enabled in the external key manager.<br>Enable the external key in<br>the external key manager and retry<br>the request.                                                                                                                          |
| Proxy returns an<br>InvalidCiphertextException    | KMSInvalidStateException<br>(Decrypt, ReEncrypt)                                                                                                                                                        | The external key store proxy<br>rejected the request because<br>the specified ciphertext or<br>encryption context is corrupted,<br>missing, or otherwise invalid.                                                                                                                                                        |
| Proxy returns an<br>invalid ciphertext            | KMSInvalidStateException<br>(Decrypt, ReEncrypt)                                                                                                                                                        | The ciphertext that the external<br>key store proxy submitted for<br>decryption, or the encryption<br>context, is corrupted, missing,<br>or otherwise invalid.                                                                                                                                                           |
| Proxy returns an<br>InvalidKeyUsageException      | XksKeyInvalidConfigurationException<br>(CreateKey)<br>KMSInvalidStateException<br>(Cryptographic operations)                                                                                            | The external key associated<br>with this KMS key in an<br>external key store does not<br>support the requested operation.<br>Enable the operation on the<br>key in your external key manager,<br>and try the request again.                                                                                                      |
| Proxy returns an<br>AuthenticationFailedException | XksProxyIncorrectAuthentication<br>CredentialException<br>(Create/UpdateCustomKeyStore)<br>CustomKeyStoreInvalidStateException<br>(CreateKey)<br>KMSInvalidStateException<br>(Cryptographic operations) | The external key store proxy<br>rejected the request because<br>it could not authenticate AWS<br>KMS. Verify the XKS proxy<br>authentication credentials for<br>your external key store and<br>update if necessary.                                                                                                      |
| Proxy returns an<br>AccessDeniedException         | KMSInvalidStateException<br>(CreateKey, Crypto operations)                                                                                                                                              | The external key store proxy<br>denied access to the operation.<br>Verify that the user and the<br>external key are both<br>authorized for this operation,<br>and try the request again.                                                                                                                                 |
| Proxy returns a<br>KeyNotFoundException           | XksKeyNotFoundException<br>(CreateKey)<br>KMSInvalidStateException<br>(Cryptographic operations)                                                                                                        | The external key associated<br>with this KMS key in an<br>external key store was not<br>found in its external key manager. If<br>the external key ID associated<br>with this KMS key is incorrect,<br>create a new KMS key with the<br>correct external key ID.                                                                  |
| Proxy returns an<br>InvalidUriPathException       | XksProxyInvalidConfigurationException<br>(Create/UpdateCustomKeyStore)<br>CustomKeyStoreInvalidStateException<br>(CreateKey)                  <br>KMSInvalidStateException<br>(Cryptographic operations)                  | The external key store proxy<br>rejected the request because<br>of an invalid URI path. Verify<br>the URI path for your external<br>key store and update if<br>necessary.                                                                                                                                                |
| Proxy returns an<br>UnsupportedOperationException | XksKeyInvalidResponseException<br>(CreateKey)<br>KMSInvalidStateException<br>(Cryptographic operations)                                                                                                 | The external key store proxy<br>rejected the request because<br>it does not support the<br>requested operation. If you<br>see this error repeatedly,<br>report it to your external<br>key store proxy administrator.                                                                                                     |
| Proxy returns a<br>DependencyTimeoutException     | XksProxyUriUnreachableException<br>(Create/UpdateCustomKeyStore)<br>CustomKeyStoreInvalidStateException<br>(CreateKey)<br>KMSInvalidStateException<br>(Cryptographic operations)                        | The external key store proxy<br>did not respond to the request<br>in the time allotted. Retry<br>the request. If you see this<br>error repeatedly, report it<br>to your external key store<br>proxy administrator.                                                                                                   |
| Proxy returns a<br>ThrottlingException            | XksProxyUriUnreachableException<br>(Create/UpdateCustomKeyStore)<br>CustomKeyStoreInvalidStateException<br>(CreateKey)<br>KMSInvalidStateException<br>(Cryptographic operations)                        | The external key store proxy<br>rejected the request due to<br>a very high request rate.<br>Reduce the frequency of your<br>calls using KMS keys in this<br>external key store.                                                                                                                                          |
| Proxy returns<br>an InternalException             | XksProxyInvalidResponseException<br>(Create/UpdateCustomKeyStore)<br>CustomKeyStoreInvalidStateException<br>(CreateKey)<br>KMSInvalidStateException<br>(Cryptographic operations)                       | The external key store proxy<br>rejected the request because<br>it cannot communicate with the<br>external key manager. Verify that the<br>external key store proxy<br>configuration is correct and<br>that the external key manager is<br>available.                                                                                    |
| AWS KMS cannot establish<br>a TCP connection      | XksProxyUriUnreachableException<br>(Create/UpdateCustomKeyStore)<br>CustomKeyStoreInvalidStateException<br>(CreateKey)<br>KMSInvalidStateException<br>(Cryptographic operations)                        | AWS KMS cannot communicate<br>with the external key store<br>proxy. This might be a transient<br>network issue. If you see this<br>error repeatedly, verify that<br>your external key store proxy<br>is active and is connected to<br>the network, and that its<br>endpoint URI is correct in your<br>external keystore. |
| AWS KMS cannot establish<br>a TLS connection      | XksProxyUriUnreachableException<br>(Create/UpdateCustomKeyStore)<br>CustomKeyStoreInvalidStateException<br>(CreateKey)<br>KMSInvalidStateException<br>(Cryptographic operations)                        | AWS KMS cannot establish a<br>TLS connection to the external<br>key store proxy. Verify the<br>TLS configuration, including<br>its certificate.                                                                                                                                                                          |
| AWS KMS encounters<br>a socket timeout            | XksProxyUriUnreachableException<br>(Create/UpdateCustomKeyStore)<br>CustomKeyStoreInvalidStateException<br>(CreateKey)<br>KMSInvalidStateException<br>(Cryptographic operations)                        | AWS KMS rejected the request<br>because the external key store<br>proxy did not respond in time.<br>Retry the request. If you see<br>this error repeatedly, report<br>it to your external key store<br>proxy administrator.                                                                                          |
| Proxy returns<br>a malformed response             | XksProxyInvalidResponseException<br>(Create/UpdateCustomKeyStore)<br>CustomKeyStoreInvalidStateException<br>(CreateKey)<br>KMSInvalidStateException<br>(Cryptographic operations)                       | AWS KMS cannot interpret the<br>response from the external<br>key store proxy. If you see<br>this error repeatedly, report<br>it to your external key store<br>proxy administrator.                                                                                                                                      |
| Custom key store is<br>not in CONNECTED<br>state  | CustomKeyStoreInvalidStateException<br>(CreateKey)<br>KMSInvalidStateException<br>(Cryptographic operations)                                                                                            | This KMS key is in a custom<br>key store that is not connected<br>to its external key store proxy.<br>Connect the external key store<br>and try the request again.                                                                                                                                                       |


<div style="page-break-after: always"/>

## Authentication

Communication between the XKS Proxy Management Fleet and XKS Proxy MUST be protected by HTTPS. Standard TLS server-side authentication MUST be used to authenticate the XKS Proxy to the XKS Proxy Management Fleet, i.e. the DNS domain name of the XKS Proxy endpoint must match the hostname specified in its server certificate.

Customers use the KMS `CreateCustomKeyStore` API to create a custom key store of type `EXTERNAL_KEY_STORE`. As part of this API call, customers specify the XKS Proxy API endpoint and credentials. The credentials include an access key id and a secret access key which are used by AWS KMS to [sign](https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html) all XKS Proxy API requests using [AWS SigV4](https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html). The same credentials are also configured by the customer at the XKS Proxy so the proxy can verify the signature independent of AWS authentication and authorization. Anyone who possesses this secret access key can make successful API calls to the XKS Proxy. The XKS Proxy administrator must ensure that this secret is not exposed to unauthorized users. [Appendix A](#appendix-a-using-sigv4-to-sign-xks-proxy-requests) describes SigV4 usage for signing requests from AWS KMS to the XKS Proxy.

An XKS proxy MUST support SigV4-based authentication of XKS API requests. Additionally, an XKS proxy SHOULD support client-side TLS authentication (aka mutual TLS or mTLS). If the XKS proxy supports mTLS, it MUST allow the customer to configure both the subject name and the root certificate authority (CA) for the client certificate. The XKS proxy MUST terminate the TLS handshake if the client presents a certificate containing a different subject name or chained to a different certificate authority. When prompted for TLS client authentication by an XKS proxy, KMS will present a certificate with a subject common name (CN) containing the service principal `cks.kms.<Region>.amazonaws.com`. For example, in eu-west-1 (Ireland), KMS will present a client certificate with CN=`cks.kms.eu-west-1.amazonaws.com`. This certificate will be chained to one of the certificate authorities associated with [Amazon Trust Services](https://www.amazontrust.com/repository/). Customers that wish to authenticate AWS KMS via mTLS MUST configure their XKS proxy to only accept client-side certs with CN=`cks.kms.<Region>.amazonaws.com` and chained to one of the Amazon Trust Services CAs. If the shared secret used in SigV4 signing is accidentally exposed to an unauthorized entity, that entity will not be able to make successful XKS API calls if the proxy only allows mTLS connections from AWS KMS.


### SigV4 credentials rotation

In accordance with security best practices, customers will want to periodically change the SigV4 credentials used to sign requests to their XKS proxy and they will prefer to do so without disrupting any workflows using XKS keys. XKS proxies SHOULD support simultaneous usage of at least two sets of SigV4 credentials for each path-prefix (each set consisting of an access key id and a secret access key). XKS proxies SHOULD allow changes to these credentials to take effect without disconnecting or shutting down the XKS proxy. With such a proxy, a customer can rotate the SigV4 credentials using the following sequence of steps:

1. Change the proxy configuration to add a new set of credentials and activate the new credentials. This will cause the proxy to start accepting signatures generated using either the old or the new set of credentials. The signature creator includes the access key id in an HTTP header to identify the secret used to generate the signature. The proxy will be able to use the access key id to verify the signature with the correct secret.
1. Call the AWS KMS `UpdateCustomKeyStore` API passing in the new credentials
1. After some time, all hosts in AWS KMS will switch over to using the new credentials
1. Change the proxy configuration to remove the old credentials

## Authorization

Customers interested in External Key Store support in KMS have asked for greater control not only on the location of the key material but also access to it. The XKS Proxy MAY use information presented as part of the request (e.g. in the requestMetadata or HTTP Authorization header) to implement another layer of fine-grained authorization controls besides those implemented by AWS policies. 

[Open Policy Agent](https://www.openpolicyagent.org/) (OPA) provides a powerful and flexible mechanism for implementing authorization checks based on policies and inputs that are specified in JSON format (see role-based access control and attribute-based access control [examples](https://play.openpolicyagent.org/)). The availability of open-source software and tools for OPA should lower the barrier for implementors to incorporate it in their XKS Proxy. 

NOTE: Since we allow creation of KMS keys based on previously created external keys, user Bob can create a KMS key B in his AWS account using the same external key that user Alice used to create a KMS key A in her AWS account. 
The ciphertext produced by calling the KMS Encrypt API for a symmetric key cryptographically binds an identifier of the backing key (the HBKid) to the ciphertext. As a result, ciphertext created by Alice using key A cannot be decrypted successfully by Bob using key B (even though both keys correspond to the same key material). However, there is no such binding for asymmetric keys. Future support for asymmetric KMS keys in external key stores can open up the possibility of a confused deputy attack - Bob is able to get KMS to decrypt data encrypted for Alice by fooling KMS into creating a key with the same underlying key material as Alice’s. To mitigate these types of issues, the XKS Proxy SHOULD support authorization, e.g. it SHOULD be possible for a customer to configure an external key to be usable only by specific AWS callers.

For XKS Proxy requests that fail due to an AccessDenied error, XKS Proxy SHOULD record sufficient details in the log to help customers identify and fix the underlying issue with the OPA policy.

## Logging

Introducing an external key manager with its own secondary authorization checks can complicate troubleshooting when things don’t work as expected. It is therefore important to log enough information on XKS Proxy and/or the external key managers to help with audit and debugging. In general, request metadata included with each API call SHOULD be logged by the XKS Proxy. The kmsRequestId field is particularly important to allow a customer to correlate AWS CloudTrail entries with log entries in XKS Proxy. 

Sensitive information such as the plaintext passed as input to the encrypt call or returned from the decrypt call MUST NOT be logged and appropriate measures must be used to ensure the integrity of the logs.

XKS Proxy and/or the external key manager MAY log additional information such as the identifier of the specific key manager that processed a request when multiple key managers serve requests for one XKS Proxy endpoint (e.g. when an key manager cluster is used in a high-availability configuration). For AccessDenied errors resulting from secondary authorization, XKS Proxy SHOULD also log the specific statement in the policy statement responsible for the denial. For performance monitoring, the XKS Proxy SHOULD log the processing time for each XKS API request, whether the request was successful and the error if the request was unsuccessful. The XKS proxy MAY choose to log this information to AWS Cloudwatch which provides in-built tools to visualize and analyze metrics. Doing so will simplify troubleshooting because the customer will be able to see metrics recorded both at the XKS proxy and within KMS in the same Cloudwatch account.


## Testing

We’ll make a test suite available which customers or vendor partners can use to test their XKS Proxy implementation. The code will need to be configured with an XKS Proxy endpoint and a set of external key Ids for previously created keys in the external key manager. The code will then exercise the APIs described in this document running both positive and negative test cases and output a report on the success/failure of these tests.

## Other considerations

### Load balancer health checks
In a production environment, an XKS proxy will likely be placed behind some type of a load balancer for resilience. Load balancers have a mechanism to poll request targets for their health status. If a target is detected as unhealthy, the load balancer will stop forwarding requests to that target until it recovers. This health check mechanism varies across load balancers but often involves a simple HTTP or HTTPS GET request to a configurable URL. A 200 OK response is interpreted as a sign of good health. In addition to the APIs mentioned above, an XKS Proxy MUST also implement the necessary health checks for the load balancers it intends to support.

Exposing the XKS Proxy as a VPC endpoint service in a customer’s Amazon VPC requires the proxy to be placed behind an AWS Network Load Balancer (NLB). Refer to the AWS NLB [public documentation](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/target-group-health-checks.html) to learn about its health check mechanisms.

### XKS proxy configuration in AWS KMS console
The AWS KMS console accepts a JSON file for specifying the XKS proxy credentials and URI endpoint during the creation or editing of a custom key store. It eliminates the error-prone process of having the user type long random credential strings into the AWS KMS console. An example file is shown below. XKS proxy implementations that incorporate a user interface SHOULD allow appropriately authenticated and authorized users to download this JSON file for use with the AWS KMS console.


**XKS Proxy Configuration File Syntax:**
```
{
  "XksProxyUriPath": string,  // for version 1, this ends in "/kms/xks/v1"
  "XksProxyAuthenticationCredential": {
    "AccessKeyId": string, // 20-30 characters, 'A' through 'Z' and '2' through '7' only
    "RawSecretAccessKey": string, // 43-64 characters, a-z, A-Z, 0-9, /, +, and =
}
```

**XKS Proxy Configuration File Example:**
```
{
    "XksProxyUriPath": "/keystores/4a0d79d6-1d1b-49fd-9dbe-799cb9c0fb3f/kms/xks/v1",
    "XksProxyAuthenticationCredential": {
        "AccessKeyId": "AKIAI2SFODNN7EXAMPLE",
        "RawSecretAccessKey": "FYtE5EFA5FT0mCc3DrGUe2sti527BitkQ0Zr9MO9fvE"
    }
}
```

### Troubleshooting
Customers preparing their XKS proxy for use with KMS will need the ability to test that the proxy can process XKS API requests correctly and do so within the KMS timeout threshold. [`curl`](https://curl.se/) is a command line tool that can be used to generate HTTP requests. Newer versions of `curl` (starting with `curl` 7.75 released in Feb 2021) support AWS SigV4 signatures. Due to its ubiquity, `curl` is an invaluable debugging tool. While other tools like `ping` and `traceroute` can only help test network connectivity, `curl` with AWS SigV4 can be used to send XKS API requests and instrument those requests.

The sample bash script and its output in [Appendix D](#appendix-d-using-curl-for-xks-api-calls) illustrate how `curl` can be used to make an XKS API call and measure the time spent in different phases of the interaction. Refer to the `curl` [man page](https://man7.org/linux/man-pages/man1/curl.1.html) for details.


<div style="page-break-after: always"/>

## Appendix A: Using SigV4 to sign XKS proxy requests

AWS SigV4 requires a shared secret (called the _secret access key_) to compute the signature and an _access key id_ which uniquely identifies the secret. Both these values must be configured into KMS as part of the `CreateCustomKeyStore` API call. The choice of access key id and secret access key MUST meet the following guidelines:

* Each secret access key should be a hard-to-guess UTF-8 string with at least 256-bits of entropy. One way to generate a good secret access key is to Base64 encode a 256-bit random value, e.g. using `openssl rand 32 | base64`. KMS will accept any combination of characters A through Z, a through z, 0 through 9, plus (+), slash (/) and equals (=).
* The access key id is a random string of length no less than 20 characters and no more than 30 characters. The only characters allowed are uppercase ‘A’ through ‘Z’ and the digits ‘2’ through ‘7’.
* An access key id must uniquely identify a secret access key, i.e. when an XKS Proxy receives an access key id in the Authorization header of an HTTP request, it MUST be able to identify the secret access key to be used for signature verification without any ambiguity.
* The access key id MUST NOT reveal any information about the secret access key
* The secret access key and access key id configured at an XKS proxy are unrelated to credentials associated with any AWS IAM principal

SigV4 uses the same key for verification as the one used for creating the signature. As part of signature verification, the XKS Proxy will recreate the signature using the authentication-key in the same manner as the the XKS Proxy Management Fleet and confirm that the computed signature matches the signature in the request. The overall steps to compute a SigV4 signature are described in the [AWS General Reference](https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html) which also includes [sample code](https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html). The rest of this Appendix provides additional details on the verification process.

Each API request from the XKS Proxy Management Fleet to the XKS Proxy will include an HTTP Authorization header containing the SigV4 signature. The general format of this header is shown below but the actual value of the access key id, date, Region and signature will vary for each request. 

General format: 
NOTE: Line breaks have been added for readability but the entire header is sent as a single line. Note that only a space separates “AWS4-HMAC-SHA256” and “Credential” (there is no comma)

```
Authorization: AWS4-HMAC-SHA256 
Credential=<access key id>/<UTC date as yyyymmdd>/<KMS Region>/kms-xks-proxy/
aws4_request, SignedHeaders=host;x-amz-date, Signature=<signature as hex string>
```

Example: 
NOTE: Line breaks have been added for readability but the entire header is sent as a single line

```
Authorization: AWS4-HMAC-SHA256 
Credential=MUBSXM6K3KMXHN6RRCXI7TWQH4NU76HYFKRSESPMTSTIBADXQQXQ/20211009/us-west-2/
kms-xks-proxy/aws4_request, 
SignedHeaders=host;x-amz-date, 
Signature=1164eaa8e79eacaa9c0df54aa42f3b300380d14bedfc08e3b319648d4abfff66
```


The date immediately following the access key id indicates the date the request was sent in YYYYMMDD format using the UTC timezone. The next field is the AWS Region (such as us-east-1 or eu-west-1). This is typically the Region in which an AWS SigV4 request is received but, for this specification, it indicates Region from which KMS called the XKS Proxy. The service indicator is the name of the service receiving the request and we use `kms-xks-proxy` for this specification. The "[StringToSign](https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html)" over which the SigV4 signature is computed includes a "HashedCanonicalRequest" and the CanonicalRequest includes a set of HTTP headers from the request. All XKS Proxy requests initiated by the XKS Proxy Management Fleet will include the Host and X-Amz-Date headers in the signature. This is indicated by setting the SignedHeaders to host;x-amz-date when using HTTP/1.1. 

<div style="page-break-after: always"/>

### Task 1: Create a canonical request

The XKS Proxy will follow the steps outlined [here](https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html) to create a canonical request. The HTTPRequestMethod will be POST for all requests from KMS. The CanonicalURI will be the API URI starting with `/<path-prefix>/kms/xks/v1`, e.g. the CanonicalURI for an encrypt API will look like  
`/<path-prefix>/kms/xks/v1/keys/<externalKeyId>/encrypt` (more in the section on the Encrypt API below). The CanonicalQueryString for the XKS Proxy API calls will be “” because the APIs described in this specification do not use query parameters. The CanonicalHeaders will include the headers from the SignedHeaders element of the Authorization. At the very least, this will include the Host header for HTTP/1.1 (or Authority Header for HTTP/2.0) containing the `<server>:<port>` from the XKS Proxy endpoint and the X-Amz-Date header containing the UTC timestamp (formatted as YYYYMMDD’T’HHMMSS’Z’) of the request. A hex encoding of the SHA-256 hash of the request payload (which includes the requestMetadata and any additional API input) forms the final part of the CanonicalRequest.

### Task 2: Create a string to sign

The next step outlined [here](https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html) composes the StringToSign. The Algorithm is always `AWS4-HMAC-SHA256,` the RequestDateTime is taken from the X-Amz-Date header, the CredentialScope is taken from the Credential element in the Authorization header and a SHA-256 hash of the CanonicalRequest from Task 1 (encoded a as lower-case hex string) is the HashedCanoicalRequest.

### Task 3: Calculate the signature

Use the access key id from the Authorization header to look up the . Derive the signing key using the Date, Region and service fields from the Credential element in the Authorization header (the service is `kms-xks-proxy`) and compute the signature as described [here](https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html).

### Task 4: Match the signature 

Verify that the signature computed at the end of Task 4 is the same as that included in the Authorization header. A match indicates successful signature verification. 

Besides signature verification, the XKS Proxy MUST also ensure that the timestamp on the request is “recent” (while accommodating for network latency and potential clock drift between the XKS Proxy Management Fleet and the XKS Proxy) to protect against replay attacks. Any requests more than 5 minutes in the past (or future, due to clock drift) SHOULD fail authentication..

<div style="page-break-after: always"/>

## Appendix B: RequestMetadata fields

The sections on individual XKS proxy APIs define which fields are included as part of the `requestMetadata`. Over time, AWS KMS may choose to include additional fields such as [`SourceIdentity`](https://aws.amazon.com/blogs/security/how-to-relate-iam-role-activity-to-corporate-identity/), `kmsRecipientAttestationImage Sha384`, `kmsRecipientAttestationPCR<PCR_ID>` (as described in [AWS KMS condition keys for AWS Nitro Enclaves](https://docs.aws.amazon.com/kms/latest/developerguide/policy-conditions.html#conditions-nitro-enclaves)) and tags associated with the AWS principal and KMS key.

Secondary authorization is an optional feature for XKS proxies. XKS proxy vendors have the flexibility to define the policy language used to express access control rules and the `requestMetadata` fields that can be used in access control policies.


<div style="page-break-after: always"/>

## Appendix C: Ciphertext Data Integrity Value (CDIV) implementation guidelines

When an Encrypt request specifies a `ciphertextDataIntegrityAlgorithm`, the corresponding response MUST include a `ciphertextDataIntegrityValue`. This section describes how this value is computed. Here, the `additionalAuthenticatedData` field is from the input of the XKS proxy encrypt API call and other fields are from the output of the encrypt API call. The `ciphertextDataIntegrityValue` is the Base64 encoded SHA-256 hash computed over the decoded

```
additionalAuthenticatedData || ciphertextMetadata || initializationVector || ciphertext || authenticationTag
```
Here "`||`" represents concatenation. If the request does not include `additionalAuthenticatedData`, the hash is computed over the decoded
```
ciphertextMetadata || initializationVector || ciphertext || authenticationTag
``` 

If the request includes `additionalAuthenticatedData` but the response does not include `ciphertextMetadata`, the hash is computed over the decoded 
```
additionalAuthenticatedData || initializationVector || ciphertext || authenticationTag
```

If neither `additionalAuthenticatedData` nor `ciphertextMetadata` is present, the hash is computed over the decoded

```
initializationVector || ciphertext || authenticationTag
```

The CDIV shown in the Encrypt response example is computed as follows. The encrypt request includes 33-bytes of AAD, and the response has 13-bytes of ciphertext metadata, 12-bytes of initialization vector, 12 bytes of ciphertext (same size as plaintext because AES-GCM is a stream cipher) and a 16-byte authentication tag. If we concatenate the `additionalAuthenticatedData`, `ciphertextMetadata`, `initializationVector`, `ciphertext` and the `authenticationTag` 
(in that order), we get an array of (33 + 13 + 12 + 12 + 16) = 86 bytes. The contents of that array (in hex) are:

```
70 72 6f 6a 65 63 74 3d  6e 69 6c 65 2c 64 65 70   // 33 bytes of AAD
61 72 74 6d 65 6e 74 3d  6d 61 72 6b 65 74 69 6e 
67 
6b 65 79 5f 76 65 72 73  69 6f 6e 3d 31            // 13 bytes of ciphertextMetadata
1c ca e5 47 0f 39 70 02  54 77 90 31               // 12 bytes of initialization vector
82 1c 64 2b 5b 71 78 33  67 de af 18               // 12 bytes of ciphertext
bc 1c 4d da 77 07 d6 81  24 47 c5 95 5e 99 b2 61   // 16 bytes of authentication tag
```

The SHA256 hash of these 86 bytes is ```a8703f2260bd8791ec2d15ea0b23e65a0631eedcf2a13a65cc82db3f47cf5ec7``` (hex) which corresponds to ```"qHA/ImC9h5HsLRXqCyPmWgYx7tzyoTplzILbP0fPXsc="``` (Base64)

NOTE: The CDIV is meant to protect against non-malicious bit flips so the computation does not incorporate the lengths of individual fields in the overall concatenation.

The recommended sequence of steps for the XKS Proxy to respond to a CDIV request are:

1. Make an encrypt request to the key manager and get the encrypt API output.
2. Compute CDIV as described above
3. Perform an XKS API decrypt call using the `additionalAuthenitcatedData` (if any, from the encrypt request) and `ciphertextMetadata` (if present, in the encrypt output), the `initializationVector`, the `ciphertext` and the `authenticationTag` fields from the encrypt output.
4. If the decryption is successful, return the encrypt API output from Step 1 along with the CDIV from Step 2. If the
decryption fails, return an error or retry from Step 1.

The ordering of the CDIV computation shown above is important. If CDIV computation is delayed until after the encryption output is used as input for the XKS decrypt API, any data corruption such as bit-flips that occur in the time after the decryption is initiated and the CDIV is computed will go undetected. The generated CDIV will still be consistent with the (now corrupted) fields in the encrypt output but future attempts to decrypt the ciphertext will fail.


The following failure scenario highlights the importance of computing the CDIV before the decrypt:

1. XKS proxy makes an encrypt request to the key manager and gets the encryption output.
2. XKS proxy uses encryption output and the `additionalAuthenticcatedData` to perform a decrypt API call
3. Encrypt API output held inside the XKS Proxy is corrupted
4. Decrypt API request from Step 2 succeeds
5. XKS Proxy computes CDIV over the (now corrupted) encrypt API output
6. XKS Proxy returns encrypt API output which is consistent with the CDIV but any attempts to decrypt the
encrypt API output will fail with InvalidCiphertextException.

<div style="page-break-after: always"/>

## Appendix D: Using curl for XKS API calls

A sample bash script illustrating the use of curl (version 7.75 or later) to send Encrypt and GetHealthStatus XKS API requests.

```
#!/bin/bash

# XKS proxy parameters
XKS_PROXY_URI_ENDPOINT=https://xks.acme.com
XKS_PROXY_URI_PATH=/path/kms/xks/v1
ACCESS_KEY_ID=HGIE2BUAFNDMBCMSQVWLGCEXAMPLE
SECRET_ACCESS_KEY=VU6W2byoiBrhDqNGbx703oL0syCAmhlQgwNUT123456
XKS_KEY_ID=b42c7fbf-de61-441c-ae24-123456789012



# See the -w option in curl
cat > curl_metrics.txt << EOF
             http_version:  %{http_version}\n
                      url:  %{url}\n
        request_body_size:  %{size_upload}\n
     response_header_size:  %{size_header}\n
       response_body_size:  %{size_download}\n
            response_code:  %{response_code}\n
 tls_verification(0=true):  %{ssl_verify_result}\n
      start_to_dns_lookup:  %{time_namelookup}s\n
     start_to_tcp_connect:  %{time_connect}s\n
   start_to_tls_handshake:  %{time_appconnect}s\n
             start_to_end:  %{time_total}s\n
EOF


# Sending an Encrypt XKS API request using curl
XKS_ENCRYPT_URI=${XKS_PROXY_URI_ENDPOINT}${XKS_PROXY_URI_PATH}/keys/${XKS_KEY_ID}/encrypt

cat > xks_encrypt_request.json << EOF
{
    "requestMetadata": {
        "awsPrincipalArn": "arn:aws:iam::123456789012:user/Alice",
        "kmsKeyArn": "arn:aws:kms:us-east-2:123456789012:/key/1234abcd-12ab-34cd-56ef-1234567890ab",
        "kmsOperation": "GenerateDataKey",
        "kmsRequestId": "4112f4d6-db54-4af4-ae30-c55a22a8dfae"
    },
    "plaintext": "SGVsbG8gV29ybGQh",
    "encryptionAlgorithm": "AES_GCM"
}
EOF

# Send Encrypt API request, view response and timing data
echo "Making Encrypt XKS API call ..."
curl --aws-sigv4  "aws:amz:us-east-1:kms-xks-proxy" \
    --user ${ACCESS_KEY_ID}:${SECRET_ACCESS_KEY} \
    -X POST -H "Content-Type:application/json" \
    --data @xks_encrypt_request.json ${XKS_ENCRYPT_URI}

echo
echo
echo "Collecting Encrypt metrics ..."
curl --aws-sigv4  "aws:amz:us-east-1:kms-xks-proxy" \
    --user ${ACCESS_KEY_ID}:${SECRET_ACCESS_KEY} \
    -X POST -H "Content-Type:application/json" \
    --data @xks_encrypt_request.json \
    -w "@curl_metrics.txt" -o encrypt.out -s \
    ${XKS_ENCRYPT_URI}



# Sending a GetHealthStatus XKS API request using curl
XKS_GET_HEALTH_STATUS_URI=${XKS_PROXY_URI_ENDPOINT}${XKS_PROXY_URI_PATH}/health

cat > xks_get_health_status_request.json << EOF
{
    "requestMetadata": {
        "kmsOperation": "KmsHealthCheck",
        "kmsRequestId": "1124f4d6-db54-4af4-ae30-c55a22a8abcd"
    }
}
EOF

# Send GetHealthStatus API request, view response and timing data
echo "Making GetHealthStatus XKS API call ..."
curl --aws-sigv4  "aws:amz:us-east-1:kms-xks-proxy" \
  --user ${ACCESS_KEY_ID}:${SECRET_ACCESS_KEY} \
    -X POST -H "Content-Type:application/json" \
    --data @xks_get_health_status_request.json  ${XKS_GET_HEALTH_STATUS_URI}

echo
echo
echo "Collecting GetHealthStatus metrics ..."
curl --aws-sigv4  "aws:amz:us-east-1:kms-xks-proxy" \
  --user ${ACCESS_KEY_ID}:${SECRET_ACCESS_KEY} \
    -X POST -H "Content-Type:application/json" \
    --data @xks_get_health_status_request.json \
    -w "@curl_metrics.txt" -o encrypt.out -s \
    ${XKS_GET_HEALTH_STATUS_URI}

```

Sample output from the script (some of the lines have been wrapped for readability):

```
$ ./curl_test.sh
Making Encrypt XKS API call ...
{"ciphertext":"yhvo7e8vvg3UoCLP","initializationVector":"BejmaUXJA08WzxJZ",
"authenticationTag":"2wsU/8i0OvB7JJkDJeiWSQ=="}

Collecting Encrypt metrics ...
             http_version:  2
                      url:  https://xks.example.com/path/kms/xks/v1/keys/
                            b42c7fbf-de61-441c-ae24-123456789012/encrypt
        request_body_size:  341
     response_header_size:  951
       response_body_size:  122
            response_code:  200
 tls_verification(0=true):  0
      start_to_dns_lookup:  0.007401s
     start_to_tcp_connect:  0.044307s
   start_to_tls_handshake:  0.222367s
             start_to_end:  0.304476s
Making GetHealthStatus XKS API call ...
{"xksProxyFleetSize":1,"xksProxyVendor":"Acme","xksProxyModel":"Acme AWS XKS Proxy 1.0","ekmVendor":"Acme","ekmFleetDetails":[{"id":"Id-1","model":"Acme HSM 1.0","healthStatus":"ACTIVE"}]}

Collecting GetHealthStatus metrics ...
             http_version:  2
                      url:  https://xks.example.com/path/kms/xks/v1/health
        request_body_size:  117
     response_header_size:  951
       response_body_size:  218
            response_code:  200
 tls_verification(0=true):  0
      start_to_dns_lookup:  0.007785s
     start_to_tcp_connect:  0.045904s
   start_to_tls_handshake:  0.236103s
             start_to_end:  0.310214s


```

<div style="page-break-after: always"/>

## Appendix E: Change log

* Version 0.0.1: Based on Aviral’s internal doc. Mainly added use of RFC 2119 terminology and best practices guidance using SHOULDs, e.g. on separating keys using domains within the external key managers, marking them non-exportable etc
* Version 0.0.2: Incorporated feedback from Ken and vendor partner. Removed key lifecycle APIs from Faythe interface. Replaced External HSM with External Key Manager. Used standard error codes between Faythe and the XKS Proxy Management Fleet (we can still convert them before exposing them to KMS API caller). Message body is used for additional disambiguation/finer granularity in describing the error.
* Version 0.0.3 (Jul 30, 2021): Added notes to suggest the message signing mechanism is under review.
* Version 0.0.4 (Aug 16, 2021): Finalized AWS SIGv4 as the mechanism for signing Faythe API requests. Changed terminology from External Key Manager (EKM) to External Key Store. Added more fields in requestMetadata. Updated error codes. Changed GETs to POSTs.
* Version 0.0.5 (Sep 7, 2021): Added back support for Faythe proxy running in a customer’s VPC (on a non-publicly routable endpoint) in the architecture diagram.
* Version 0.0.6 (Sep 22, 2021): Added Appendix A on special considerations for using SigV4 in the context of this document and Appendix B on open questions. Updated terminology, e.g. replaced KMS internal fleet names with external names, Faythe is now the External Key Store Proxy or XKS Proxy, replaced eks in the URLs with xks, Replaced EncryptionContext with a generic AdditionalAuthenticatedData (AAD) field which simplifies the XKS Proxy implementation (because it no longer needs to worry about canonicalizing a set of key-value pairs) and allows KMS to include additional data, such as the proprietary ciphertext blob header,  in the AAD.
* Version 0.0.7 (Sep 28, 2021): Relaxed the constraint on API endpoint to include a path-prefix, i.e. the endpoint can look like `https://<server>:<port>/<path-prefix>/kms/xks/v1`, as opposed to
`https://<server>:<port>/kms/xks/v1.` Specified the set of allowed characters in an external key Id: uppercase or lowercase letters A through Z, digits 0 through 9 and the hyphen. Also added guidance on ensuring the secrets used for SigV4 verification are adequately protected.
* Version 0.0.8 (Oct 11, 2021): Updated high-level architecture diagram to eliminate the middle option since it was equivalent to the third option from a connectivity perspective. Clarified what error is thrown (IncorrectKeyException) if the externalKeyId passed to an API call for v1 corresponds to a key with a type other than AES-256. **Removed the `<path-prefix>` from the endpoint URI because having that flexibility for the VPC-connectivity option introduces more complexity on the KMS API (this reverts a change that was introduced in Version 7).** Clarified that requests with a timestamp not within 5 minutes of the proxy’s timestamp should fail authentication. Updated ErrorMessage strings. Added a new error InvalidKeyUsageException which is thrown if the AES encrypt/decrypt operation is invoked on a key mean for different usage, e.g. for HMAC or asymmetric Sign/Verify. Removed the IncorrectKeyException for Decrypt because the operation cannot distinguish between IncorrectKeyException and IncorrectCiphertextException (look for strikethrough text in the Errors table).
* Version 0.0.9 (Oct 27, 2021): Re-introduced path-prefix in the XKS proxy endpoint, the endpoint can look like `https://<server>:<port>/<path-prefix>/kms/xks/v1`, as opposed to
`https://<server>:<port>/kms/xks/v1`.  Expanded the GetHealthStatus response to include information on multiple HSMs in a cluster. The additional information can be used by AWS KMS to process TPS limit increase requests from customers. Clarified that the proxy may create test keys (but not keys associated with KMS keys) and invoke cryptographic operation on them as part of a deep healthcheck. Clarified that this API MUST be excluded from authorization on the XKS Proxy.
* Version 0.0.10 (Nov 12, 2021): Mentioned the possibility of including KMS condition keys for AWS Nitro Enclaves in requestMetadata. Specified size of IV must be exactly 96 bits. Updated the description of plaintext and ciphertext for both Encrypt and Decrypt APIs to clarify the size of the the input the XKS Proxy must accept and the 20-byte limit on extra bytes it may add during encrypt. Added requirement on XKS Proxy to support up to 8192 bytes of AAD. Added the ability to request a Ciphertext Data Integrity Value (CDIV) in the Encrypt API. Added an example in the Encrypt API description illustrating CDIV computation. Removed authentication mechanism between KMS and XKS Proxy from the list of Open Issues: we are moving forward with a combination of TLS server-side authentication (for authenticating the XKS Proxy to KMS) and SigV4 (for authenticating KMS to the XKS Proxy).
* Version 0.0.11 (Jan 3, 2021): This version incorporates a number of recommendations received from internal and external feedback providers
    * End GetKeyMetadata endpoint in “metadata” for consistency with other APIs
    * Allow the IV to be either 12 or 16 bytes
    * Rename keyState in GetKeyMetadata response to keyStatus to distinguish it from KMS keyState
    * Require access key id to be specified independently (do not derive it from the Authentication secret)
    * Specify keyUsage as a list, e.g. [“ENCRYPT”, “DECRYPT”]
    * Change encryption algorithm to AES_GCM (instead of AES_GCM_256)
    * Separate out vendor-specific data into its own field CiphertextMetadata, include it in CDIV computation example, and require it to be included in the computation of the authentication tag
    * Improve text on health checks
    * Remove IncorrectKeyException
    * Allow underscore as a valid character in the externalKeyId
    * Called out HTTP/1.1 or later and TLS 1.2 or later with specific cipher suites providing perfect forward secrecy.
* Version 0.0.12 (Feb 02, 2022): Updated the description for the keyArn field in request metadata associated with the GetKeyMetadata API (it is no longer REQUIRED, KMS will include it when the kmsOperation is DescribeKey but not for CreateKey). Added GetHealthStatus as one of the APIs that can throw an InvalidStateException.
* Version 0.0.13 (Feb 28, 2022): This version incorporates the following changes:
    * Changed wording in the description of the two ways in which the XKS Proxy service is exposed to KMS. Previous wording suggested that exposing the service as a VPC endpoint service requires the XKS proxy to be in the customer’s Amazon VPC. This is not the case. The customer just needs an NLB in their VPC. The NLB can be configured to use private IP addresses in its target group. Those IP addresses can be in the customer’s data center as long as those IP addresses are reachable from the VPC. 
    * Clarified that kmsRequestId is part of the requestMetadata accompanying a GetHealthStatus request only if the request is made as part of the KMS `CreateCustomKeyStore` or `ConnectCustomKeyStore` API
    * Added InvalidUriPathException (HTTP Code 404) for situations where the XKS Proxy receives a request with an invalid URI path.
    * Added Appendix B with guidelines on CDIV implementation.
* Version 0.0.14 (Mar 31, 2022):
    * Updated URIs everywhere to show optional portions in square brackets.
    * Added a section on “Other Considerations” that talks about load balancer health checks an XKS Proxy must implement.
    * Clarified that the secret access key can be any UTF-8 string with sufficient entropy and Base64 encoding a 32-byte random value is just one of the possible ways of generating a good secret access key. Also mentioned the list of characters allowed in the secret access key.
    * Clarified a max character limit of 128 on the `XksProxyUriPath` and mentioned the list of allowed characters.
    * Clarified that GetKeyMetadata MUST not return more than ten values for keyUsage
    * Clarified that GetHealthStatus MUST not return more than ten entries for ekmFleetDetails
    * Removed all mention of CDIV. For the foreseeable future, KMS will handle this internally and we can simplify the specification and make it easier to implement. When we reintroduce CDIV, we will require the XKS Proxy to include the complete AAD in the CDIV computation along with the ciphertextMetadata, IV, ciphertext and authentication tag.
    * Added this text for every description of kmsOperation: “The XKS Proxy MUST NOT reject a request as invalid if it sees a kmsOperation other than those listed for this API call.” See the kmsOperation description in GetKeyMetadata for justification.
* Version 0.0.15 (Apr 06, 2022):
    * Changed requestMetadata specification for GetHealthStatus to always include a requestId and kmsOperation.
    * Updated Error Code list to clarify InvalidStateException can be returned for all APIs.
* Version 0.0.16 (Jun 23, 2022):
    * Reintroduced CiphertextDataIntegrityValue (CDIV) and included AAD into the CDIV computation. Added Appendix C with CDIV computation guidelines.
    * Added new architecture diagram showing VPC endpoint connectivity with XKS proxy in and outside the AWS data center.
    * Removed optional port in URIs since KMS APIs require the proxy to run on the default HTTPS port.
    * Updated text to indicate the XksProxyUriEndpoint is always specified irrespective of connectivity option.
    * Mentioned 500ms KMS timeout and how the proxy may use caching of the deep health check result to meet this constraint.
    * Added a description of the XKS Proxy configuration file under Other Considerations
    * Added a recommendation for the XKS Proxy to support client-side TLS authentication.
* Version 0.0.17 (Jul 15, 2022):
    * Remove error messages from the JSON payload in error responses from the proxy since KMS is ignoring them.
    * Added a table under KMS Considerations for Error Codes indicating the specific KMS exceptions and messages returned to the KMS caller when the XKS proxy reports an error.
    * Added guidance on including the length of the ciphertext metadata before including it in the AAD input for the external HSM.
* Version 0.0.18 (Aug 2, 2022):
    * Added clarifying text in multiple places: separated out recommended TLS cipher suites by TLS version, replaced Base-64 and base64 references with Base64 for consistency, mentioned that XKS proxy must be able to fall back to HTTP 1.1.
    * Recommended including the length of both the `additionalAuthenticatedData` and `ciphertextMetadata` when creating the AAD for the external HSM
    * Reworded Appendix B to suggest KMS may expand `requestMetadata` fields in the future but each XKS proxy vendor can define their own policy language and choose which of those fields are usable in access control decisions.
* Version 0.0.19 (Aug 3, 2022):
    * Fix typo in KMS Exception Message.
* Version 0.0.20 (Aug 3, 2022):
    * Clarify the endianness of the 2-byte AAD length in constructing the AAD input of AES/GCM to the external HSM.
* Version 0.0.21 (Aug 16, 2022):
    * Added a new section on Troubleshooting using curl under Other Considerations.
    * Added a new subsection under Authentication describing how an XKS proxy should support rotation of SigV4 credentials.
    * Changed 500ms KMS timeout threshold to 250ms and the ping latency between customer data center and AWS data center to be 35ms (down from 100ms).
* Version 0.0.22 (Aug 19, 2022):
    * Changed how KMS reports access denied and invalid ciphertext errors from the proxy, both of these are now reported as KMSInvalidStateException.
    * Added a new entry for ThrottlingException in the error codes section. This provides a mechanism for the proxy to implement back pressure on a caller when the request rate is too high. Added a corresponding entry in the table of KMS exceptions. Mentioned that an XKS proxy may implement independent request quotas on each path prefix and respond with a ThrottlingException if that quota is exceeded.
 * Version 0.9.6 (Sep 12, 2022):
    * The XKS proxy may include an optional errorMessage in the JSON body when reporting an API failure.
    * Updated the text of error messages KMS reports to its callers for various exceptions.
    * Renumbered pre-GitHub version numbers, e.g. pre-GitHub version number X was renumbered 0.0.X. The jump in version number reflects we are getting close to finalizing v1 of the XKS Proxy API specification.
 * Version 0.9.7 (Oct 10, 2022):
    * Allow period as a valid character in the `externalKeyId`.
 * Version 0.9.8 (Oct 12, 2022):
    * Changes to render the architecture diagram and tables correctly when viewing the specification markdown on GitHub.
    * Fixed anchor link navigation, added a table of contents and removed extraneous asterisks in a couple of headers.
    * Removed unnecessary reference to post-quantum TLS ciphersuites in S2N
 * Version 0.9.9 (Oct 28, 2022):
    * Changed heading capitalization to match AWS documentation norms
    * Moved "Error codes" out of the "API operations" section
    * Spelt out CDIV in the title of Appendix E
    * Removed reference to Base64 when talking about secret access key
 * Version 1.0.0 (Nov 10, 2022):
    * Updated terminology (preferring external key manager over external HSM) to match our public docs. This is also reflected in the KMS error messages.
    * Replaced TBD references with actual numbers for health status polling frequency and TPS quota on AWS KMS external key stores.
