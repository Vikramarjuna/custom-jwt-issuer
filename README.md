# Go JWT Issuer Application

This application is a simple, customizable JSON Web Token (JWT) issuer built in Go. It can be used as a command-line utility for key generation and token signing, or deployed as an HTTP server to provide JWKS (JSON Web Key Set) and on-demand JWT issuance. It's ideal for development, testing, and demonstrating JWT authentication flows.

## Features

- **RSA Key Pair Generation:** Generate a private key (for signing) and its corresponding public key (for verification) locally.
- **JWKS Endpoint:** Serves the public key in standard JWKS format (`/.well-known/jwks.json`).
- **JWT Generation Endpoint:** Accepts `POST` requests with custom claims to issue signed JWTs.
- **JWT Verification Endpoint:** Accepts `POST` requests with JWTs in the Authorization header to verify their validity and decode their contents, similar to `jwt.io`.
- **Configurable:** Key parameters (Issuer, Audience, Algorithm, Key ID, Listen Port) are configurable via environment variables.
- **Containerized:** Dockerfile provided for easy packaging and deployment.
- **CLI Mode:** Command-line interface for direct key generation and token signing.

---

## Getting Started

### 1. Generate RSA Keys and JWKS

This step generates your private and public keys, and the JWKS JSON needed for your application to serve.

```sh
go run main.go generate-keys
```

The output will include:
- `--- PRIVATE KEY (Save this content to private_key.pem) ---`
- `--- PUBLIC KEY (JWKS Format - For review) ---`
- `--- BASE64-ENCODED JWKS STRING (Copy this for later use in deployments if needed) ---`
- `--- IMPORTANT: Note your KID: <your-kid> ---`
- `--- IMPORTANT: Note your ALG: <your-alg> ---`

**Important:**
- Save the content under `--- PRIVATE KEY ---` into a file named `private_key.pem`. Keep this file secure and never commit it to public repositories.
- Note the BASE64-ENCODED JWKS STRING, your KID, and your ALG. You'll need these for Kubernetes and JWT generation.

### 2. Generate JWT
```sh
# Example 1: Generate with defaults for most claims, only requiring private key file
# 'sub' will default to "cli_user", 'iss' and 'aud' from global config, etc.
./custom-jwt-issuer generate-jwt private_key.pem

# Example 2: Generate with a custom subject, and default issuer/audience/times
./custom-jwt-issuer generate-jwt private_key.pem '{"sub":"my-app-client"}'

# Example 3: Generate with a custom role, subject, and default issuer/audience/times
./custom-jwt-issuer generate-jwt private_key.pem '{"sub":"admin-user", "role":"admin"}'

# Example 4: Override issuer and audience
./custom-jwt-issuer generate-jwt private_key.pem '{"sub":"external-service", "iss":"https://external.example.com", "aud":["api-scope-1", "api-scope-2"]}'
```

### 3. Build and Push the Docker Image

This packages your Go application into a Docker image, making it portable.

```sh
docker buildx build --platform linux/amd64,linux/arm64 -t your-docker-repo/custom-jwt-issuer:your-tag --push .
```
- Replace `your-docker-repo` with your Docker Hub username or private registry prefix.
- Replace `your-tag` with a version (e.g., `v1.0.0`).

### 4. Run as a Docker Container (Local Test)

You can test the application locally as a Docker container before deploying to Kubernetes.

```sh
docker run -p 8080:8080 \
  -e LISTEN_PORT="8080" \
  -e JWT_ISSUER="https://my-go-issuer.example.com" \
  -e JWT_AUDIENCE="your-api-audience" \
  -e JWKS_ALG="<YOUR_ALG_FROM_STEP_2>" \
  -e JWKS_KID="<YOUR_KID_FROM_STEP_2>" \
  -v "$(pwd)/private_key.pem:/app/private_key.pem:ro" \
  your-docker-repo/custom-jwt-issuer:your-tag
```
- The `-v` flag mounts your local `private_key.pem` into the container.

### 5. Deploy to Kubernetes (Optional)

If you plan to deploy to a Kubernetes cluster, you'll need the `custom-jwt-issuer-k8s.yaml` manifest.

#### Create Kubernetes Secret for Private Key

```sh
kubectl create secret generic custom-jwt-private-key --from-file=private_key.pem=private_key.pem -n jwt-issuer
```

#### Update `custom-jwt-issuer-k8s.yaml`
- Replace `your-docker-repo/custom-jwt-issuer:your-tag` with the actual image you built and pushed.
- Update `JWT_ISSUER`, `JWT_AUDIENCE`, `JWKS_ALG`, `JWKS_KID` environment variables in the Deployment section to match the values you noted in Step 2.
- Ensure the `stringData` section of the `custom-jwt-private-key` Secret in the YAML is configured to reference the created secret (if you used `kubectl create secret`).

#### Apply Kubernetes Manifests

```sh
kubectl apply -f custom-jwt-issuer-k8s.yaml
```

---

## Verify Deployment

```sh
kubectl get pods -n jwt-issuer -l app=custom-jwt-issuer
kubectl get svc -n jwt-issuer custom-jwt-issuer
kubectl logs -f -n jwt-issuer $(kubectl get pod -n jwt-issuer -l app=custom-jwt-issuer -o jsonpath='{.items[0].metadata.name}') -c app
```
- Look for `Private key loaded successfully` and `Listening on 0.0.0.0:8080` in the logs.

---

## Using the Running Application

Once the application is running (either locally in Docker or in Kubernetes), you can interact with its APIs.

### 1. Get JWKS Endpoint (`/jwks`)

- **If running locally in Docker:**
  ```sh
  curl http://localhost:8080/.well-known/jwks.json
  ```
- **If running in Kubernetes (from within the cluster, e.g., a debug pod):**
  ```sh
  kubectl exec -it <YOUR_DEBUG_POD_NAME> -n <YOUR_DEBUG_POD_NAMESPACE> -- curl http://custom-jwt-issuer.jwt-issuer.svc.cluster.local:8080/.well-known/jwks.json
  ```
- You should see the JWKS JSON output.

### 2. Generate JWT Endpoint (`/token`)

This endpoint accepts POST requests with claims in a JSON body to issue a signed JWT.

- **If running locally in Docker:**
  ```sh
  curl -v -X POST \
    -H "Content-Type: application/json" \
    -d '{"sub":"testuser","role":"admin","aud":"your-api-audience"}' \
    http://localhost:8080/token
  ```
- **If running in Kubernetes (from within the cluster):**
  ```sh
  kubectl exec -it <YOUR_DEBUG_POD_NAME> -n <YOUR_DEBUG_POD_NAMESPACE> -- curl -v -X POST \
    -H "Content-Type: application/json" \
    -d '{"sub":"testuser","role":"admin","aud":"your-api-audience"}' \
    http://custom-jwt-issuer.jwt-issuer.svc.cluster.local:8080/token
  ```
- The output will be a JSON response containing the `access_token`. Copy this token.

### 3. Verify JWT Endpoint (`/verify-jwt`)

This endpoint allows you to verify a JWT's signature and decode its contents.

- **If running locally in Docker:**
  ```sh
  curl -v -H "Authorization: Bearer <YOUR_GENERATED_JWT_TOKEN>" \
       http://localhost:8080/verify-jwt
  ```
- **If running in Kubernetes (from within the cluster):**
  ```sh
  kubectl exec -it <YOUR_DEBUG_POD_NAME> -n <YOUR_DEBUG_POD_NAMESPACE> -- curl -v -H "Authorization: Bearer <YOUR_GENERATED_JWT_TOKEN>" \
       http://custom-jwt-issuer.jwt-issuer.svc.cluster.local:8080/verify-jwt
  ```
- This will return a JSON object showing `isValid: true` and the decoded header/payload, or `isValid: false` with an error message.

---

This comprehensive setup provides a robust and flexible custom JWT issuer for your testing needs.

