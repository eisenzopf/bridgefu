# Browser example

This page expects a same-origin application endpoint at
`POST /demo/bridgefu-route`. That endpoint should authenticate the user with an
HTTP-only session, create `POST /v1/routes/{route_id}/calls` server-side, and
return the Bridgefu response unchanged. Do not expose the Bridgefu control API
bearer to JavaScript.

Build and serve the SDK directory:

```sh
npm ci
npm run build
python3 -m http.server 8080
```

Open `http://localhost:8080/example/`. For local development, Bridgefu's
attachment still needs a reachable WSS endpoint; an insecure signaling socket
is intentionally not enabled by this example.
