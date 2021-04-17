# How to create an OpenID Connect 1.0 Provider

This is an example of OpenID Connect 1.0 server in [FastAPI](https://fastapi.tiangolo.com/) and [Authlib](https://authlib.org/).

- FastAPI Repo: <https://github.com/tiangolo/fastapi>
- Authlib Repo: <https://github.com/lepture/authlib>

# Auth Code Flow
The flow includes the following steps:
The client prepares a link to the authorization server and opens the link for user in an user agent (browser). The link includes information that allows the authorization server to identify and respond to the client.
User enters their credentials on the new page.
Credentials are sent to authorization server via the user agent (browser).
The authorization server validates the credentials and redirects user back to the client with an authorization code.
The client talks with the authorization server, confirms its identify and exchanges the authorization code for an access token and optionally a refresh token.
The client uses the access token to access resources on the resource server.
---

## Take a quick look

This is a ready to run example, let's take a quick experience at first. To
run the example, we need to install all the dependencies:

```bash
$ pip install -r requirements.txt
```

Set FastAPI and Authlib environment variables:

```bash
# disable check https (DO NOT SET THIS IN PRODUCTION)
$ export AUTHLIB_INSECURE_TRANSPORT=1
```

Create Database and run the development server:

```bash
$ uvicorn main:app --host 127.0.0.1 --port 5000 --reload
```

Now, you can open your browser with `http://127.0.0.1:5000/`.

Before testing, we need to create a client:

![create a client](https://user-images.githubusercontent.com/290496/64176341-35888100-ce98-11e9-8395-fd4cdc029fd2.png)

**NOTE: YOU MUST ADD `openid` SCOPE IN YOUR CLIENT**

Let's take `authorization_code` grant type as an example. Visit:

```bash
$ curl -i -XPOST 'http://127.0.0.1:5000/oauth/authorize?client_id=D3JlWRV57SjsiFR52stiEBrM&response_type=code&scope=openid+profile&nonce=abc' -F uuid=XXXXXXX

$ curl -i -XPOST http://127.0.0.1:5000/oauth/authorize?client_id=${CLIENT_ID}&response_type=code&scope=openid+profile&nonce=abc -F uuid=XXXXXXX
```

If you get the error below:
```{
  "error": "invalid_request",
  "error_description": "Redirect URI http://www.example.com is not supported by client.",
  "state": "324234234"
}
```
It means that the entry in the DB for endpoint mismatch the redirect URL provided in the request
They should match.

Here is an example of a valid redirect URL
```
    http://localhost:5000/oidc/auth/cb/
```


After that, you will be redirect to a URL. For instance:

```bash
HTTP/1.1 100 Continue

HTTP/1.1 302 Found
date: Tue, 06 Oct 2020 22:21:12 GMT
server: uvicorn
location: https://example.com/?code=RSv6j745Ri0DhBSvi2RQu5JKpIVvLm8SFd5ObjOZZSijohe0
content-length: 2
content-type: application/json
```

Copy the code value, use `curl` to get the access token:

```bash
$ curl -u "${CLIENT_ID}:${CLIENT_SECRET}" -XPOST http://127.0.0.1:5000/oauth/token -F grant_type=authorization_code -F code=RSv6j745Ri0DhBSvi2RQu5JKpIVvLm8SFd5ObjOZZSijohe0 -F scope=profile
```

Now you can access `/oauth/userinfo`:

```bash
$ curl -H "Authorization: Bearer ${access_token}" http://127.0.0.1:5000/oauth/userinfo
```