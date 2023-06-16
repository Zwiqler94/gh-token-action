import {
  debug,
  error,
  setFailed,
  getInput,
  InputOptions,
  setOutput,
  saveState,
} from "@actions/core";
import { getOctokit, context } from "@actions/github";
import { App } from "@octokit/app";
import { Octokit } from "@octokit/core";
import { sign } from "jsonwebtoken";
import _sodium from "libsodium-wrappers";

// const debug = (val: any) => core.debug(JSON.stringify(val));

async function run() {
  debug("Start Token Check");
  debug(`Repo info: ${JSON.stringify(context.repo)}`);

  // const optionalInput: InputOptions = { required: false };
  const token = getInput("token");
  const userRefreshToken = getInput("userRefreshToken");
  const privateKey = getInput("privateKey");
  const clientId = getInput("clientId");
  const clientSecret = getInput("clientSecret");
  const appId = getInput("appId");
  let refreshAccessTokenResponse;
  let publicKeyResp: any;

  debug(
    JSON.stringify({
      inputs: {
        token,
        userRefreshToken,
        privateKey,
        clientId,
        clientSecret,
        appId,
      },
    })
  );

  const jwt = generateJWT(appId, privateKey);
  let installId = await getAppInstallId(jwt);

  const app = new App({
    appId,
    privateKey,
    oauth: { clientId, clientSecret },
  });

  const octo: Octokit = await app.getInstallationOctokit(installId);
  const octoInstallToken = await octo.request(
    "POST /app/installations/{installation_id}/access_tokens",
    {
      installation_id: installId,
      repository: context.repo,
    }
  );

  if (context.actor === "nektos/act") {
    setOutput("appToken", octoInstallToken.data.token);
  }

  try {
    publicKeyResp = await getPublicKey(
      context.repo,
      octo
    );

    if (token.length > 0) {
      try {
        const checkToken = await app.oauth.checkToken({ token });
        debug(JSON.stringify(checkToken));
        updateSecret(
          "USER_ACCESS_TOKEN",
          publicKeyResp,
          checkToken.data.token,
          octo
        );
      } catch (error: any) {
        const refreshTokenResp = await app.oauth.refreshToken({
          refreshToken: userRefreshToken,
        });
        updateSecret(
          "USER_ACCESS_TOKEN",
          publicKeyResp,
          refreshTokenResp.data.access_token,
          octo
        );
        updateSecret(
          "USER_REFRESH_TOKEN",
          publicKeyResp,
          refreshTokenResp.data.refresh_token,
          octo
        );
      }
    }
  } catch (error) {
    console.log(error);
  }

  debug(JSON.stringify(octoInstallToken.data));
  debug(JSON.stringify({ octoApp: octo }));

  try {
    if (token.length > 0) {
      try {
        debug("start check token");
        const validTokenResponse = await octo.request(
          "POST /applications/{client_id}/token",
          {
            client_id: clientId,
            access_token: token,
            headers: {
              "X-GitHub-Api-Version": "2022-11-28",
            },
          }
        );
        debug(JSON.stringify(validTokenResponse));
        debug("Token is Valid, Carry On...");

        return;
      } catch (error2: any) {
        error(error2);
        debug("Refreshing token");

        refreshAccessTokenResponse = await app.oauth.refreshToken({
          refreshToken: userRefreshToken,
        });

        debug(JSON.stringify({ refreshFinished: refreshAccessTokenResponse }));

        debug("Get Public Key");
        publicKeyResp = await getPublicKey(
          context.repo,
          octo
        );

        debug(JSON.stringify({ publicKeyResp }));

        try {
          try {
            try {
              debug("Begin Secret Updates");
              const updateAccessTokenResp = await updateSecret(
                "USER_ACCESS_TOKEN",
                publicKeyResp,
                refreshAccessTokenResponse.data.access_token,
                octo
              );

              debug(JSON.stringify({ access: updateAccessTokenResp }));

              const updateRefreshTokenResp = await updateSecret(
                "USER_REFRESH_TOKEN",
                publicKeyResp,
                refreshAccessTokenResponse.data.refresh_token,
                octo
              );

              debug(JSON.stringify({ refresh: updateRefreshTokenResp }));
              debug("Finish Secret Updates");
            } catch (error3: any) {
              error(error3);
              throw Error(JSON.stringify({ failedSecretUpdate: error3 }));
            }
          } catch (error5: any) {
            error(error5);
            throw Error(error5);
          }
        } catch (error6: any) {
          debug(JSON.stringify({ error6 }));
          throw Error(error6);
        }
      }
    }
  } catch (error7: any) {
    error("Token Refresh Failed, Refresh Manually");
    setFailed(error7);
  }
}

async function getPublicKey(
  options: {
    owner: string;
    repo: string;
  },
  app: Octokit
) {
  debug(`repo: ${JSON.stringify(options)}`);

  try {
    const publicKeyResp = await app.request(
      "GET /repos/{owner}/{repo}/actions/secrets/public-key",
      {
        ...context.repo,
        headers: {
          "X-GitHub-Api-Version": "2022-11-28",
        },
      }
    );
    debug(`Public Key Resp: ${JSON.stringify(publicKeyResp)}`);
    return publicKeyResp;
  } catch (error9: any) {
    error(error9);
    throw Error(error9);
  }
}

async function updateSecret(
  secretName: string,
  publicKeyResp: any,
  valueToStore: any,
  app: Octokit
) {
  debug(`\nSecret to update ${secretName}\n`);
  await _sodium.ready;
  const sodium = _sodium;
  let binkey = sodium.from_base64(
    publicKeyResp.data.key,
    sodium.base64_variants.ORIGINAL
  );

  let binsec = sodium.from_string(valueToStore);

  let encBytesAccessToken = sodium.crypto_box_seal(binsec, binkey);

  let completedSecret = sodium.to_base64(
    encBytesAccessToken,
    sodium.base64_variants.ORIGINAL
  );

  debug(
    JSON.stringify({ binkey, binsec, encBytesAccessToken, completedSecret })
  );

  try {
    const updateSecretResp = await app.request(
      "PUT /repos/{owner}/{repo}/actions/secrets/{secret_name}",
      {
        ...context.repo,
        secret_name: secretName,
        encrypted_value: completedSecret,
        key_id: publicKeyResp.data.key_id,
        headers: {
          "X-GitHub-Api-Version": "2022-11-28",
        },
      }
    );
    debug(JSON.stringify(updateSecretResp));
    return updateSecretResp;
  } catch (error9: any) {
    throw Error(error9);
  }
}

async function getAppInstallId(jwt: string) {
  const installationOcto = getOctokit(jwt);
  const resp = await installationOcto.request("GET /app/installations", {
    headers: {
      "X-GitHub-Api-Version": "2022-11-28",
    },
  });

  let installId = 0;
  if (resp.data[0].app_slug === "actions-pr-approval") {
    installId = resp.data[0].id;
  }
  return installId;
}

function generateJWT(appId: string, privateKey: string) {
  const issuedAtTime = Math.floor(Date.now() / 1000) - 60;
  const expirationTime = issuedAtTime + 10 * 60;
  debug(JSON.stringify({ issuedAtTime, expirationTime }));
  const jwt = sign(
    { iat: issuedAtTime, exp: expirationTime, iss: appId },
    privateKey,
    {
      algorithm: "RS256",
    }
  );
  return jwt;
}

run();
