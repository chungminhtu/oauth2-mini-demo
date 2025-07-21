// oidc-provider-refresh-token.spec.ts

import { Provider } from "oidc-provider";
import { createServer, Server } from "http";
import request from "supertest";
import { promisify } from "util";
import jwt from "jsonwebtoken";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import axios from "axios";

describe("OIDC Provider Refresh Token E2E Test", () => {
  let provider: Provider;
  let server: Server;
  let oidcConfig: any;

  const issuer = "http://localhost:3000";
  const clientId = "test_client_id";
  const clientSecret = "test_client_secret";

  const account = {
    accountId: "test_account",
    async claims() {
      return {
        sub: "test_account",
        email: "test@example.com",
        email_verified: true,
      };
    },
  };

  beforeAll(async () => {
    provider = new Provider(issuer, {
      clients: [
        {
          client_id: clientId,
          client_secret: clientSecret,
          grant_types: ["authorization_code", "refresh_token"],
          redirect_uris: ["http://localhost:8080/cb"],
        },
      ],
      features: {
        devInteractions: { enabled: false },
        resourceIndicators: { enabled: true },
      },
      scopes: ["openid", "email", "offline_access"],
      claims: {
        openid: ["sub"],
        email: ["email", "email_verified"],
      },
      rotateRefreshToken: true,
      ttl: {
        AccessToken: 1 * 60 * 60, // 1 hour in seconds
        AuthorizationCode: 10 * 60, // 10 minutes in seconds
        IdToken: 1 * 60 * 60, // 1 hour in seconds
        DeviceCode: 10 * 60, // 10 minutes in seconds
        RefreshToken: 1 * 24 * 60 * 60, // 1 day in seconds
      },
    });

    // Add a custom findAccount function
    provider.use(async (ctx, next) => {
      ctx.oidc.account = account;
      await next();
    });

    server = createServer(provider.callback());
    await promisify(server.listen.bind(server))(3000);

    // Fetch OIDC configuration
    const configResponse = await axios.get(
      `${issuer}/.well-known/openid-configuration`
    );
    oidcConfig = configResponse.data;
    console.log({ oidcConfig });
    
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("should obtain and use a refresh token", async () => {
    // Step 1: Initiate authorization request
    const authorizationUrl = getAuthorizationUrl();
    const response = await request(server).get(
      authorizationUrl.pathname + authorizationUrl.search
    );
    expect(response.status).toBe(302);

    const callbackUrl = new URL(response.headers.location as string);
    const code = callbackUrl.searchParams.get("code");
    expect(code).toBeTruthy();

    // Step 2: Exchange authorization code for tokens
    const tokenResponse = await request(server)
      .post(new URL(oidcConfig.token_endpoint).pathname)
      .type("form")
      .send({
        grant_type: "authorization_code",
        code,
        redirect_uri: "http://localhost:8080/cb",
        client_id: clientId,
        client_secret: clientSecret,
      });

    expect(tokenResponse.status).toBe(200);
    expect(tokenResponse.body).toHaveProperty("access_token");
    expect(tokenResponse.body).toHaveProperty("refresh_token");
    expect(tokenResponse.body).toHaveProperty("id_token");

    const refreshToken = tokenResponse.body.refresh_token;

    // Step 3: Use refresh token to get new access token
    const refreshResponse = await request(server)
      .post(new URL(oidcConfig.token_endpoint).pathname)
      .type("form")
      .send({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
        client_id: clientId,
        client_secret: clientSecret,
      });

    expect(refreshResponse.status).toBe(200);
    expect(refreshResponse.body).toHaveProperty("access_token");
    expect(refreshResponse.body).toHaveProperty("refresh_token");
    expect(refreshResponse.body).toHaveProperty("id_token");

    // Verify that we got a new access token
    expect(refreshResponse.body.access_token).not.toBe(
      tokenResponse.body.access_token
    );

    // Step 4: Verify the new access token
    const introspectionResponse = await request(server)
      .post(new URL(oidcConfig.introspection_endpoint).pathname)
      .type("form")
      .send({
        token: refreshResponse.body.access_token,
        client_id: clientId,
        client_secret: clientSecret,
      });

    expect(introspectionResponse.status).toBe(200);
    expect(introspectionResponse.body).toHaveProperty("active", true);
    expect(introspectionResponse.body).toHaveProperty(
      "scope",
      "openid email offline_access"
    );

    // Step 5: Verify ID token
    const idToken = refreshResponse.body.id_token;
    const decodedIdToken: any = jwt.decode(idToken);

    expect(decodedIdToken).toBeTruthy();
    expect(decodedIdToken.sub).toBe("test_account");
    expect(decodedIdToken.email).toBe("test@example.com");
    expect(decodedIdToken.email_verified).toBe(true);
  });

  function getAuthorizationUrl(): URL {
    const authUrl = new URL(oidcConfig.authorization_endpoint);
    authUrl.searchParams.append("client_id", clientId);
    authUrl.searchParams.append("redirect_uri", "http://localhost:8080/cb");
    authUrl.searchParams.append("response_type", "code");
    authUrl.searchParams.append("scope", "openid email offline_access");
    authUrl.searchParams.append("prompt", "consent");
    return authUrl;
  }
});
