import {
  debug,
  error,
  getBooleanInput,
  getInput,
  info,
  setFailed,
  setOutput,
  setSecret,
} from "@actions/core";
import { context } from "@actions/github";
import { App } from "@octokit/app";
import _sodium from "libsodium-wrappers";

type Inputs = {
  token: string;
  userRefreshToken: string;
  privateKey: string;
  clientId: string;
  clientSecret: string;
  appId: string;
  installationId?: number;
  exposeTokens: boolean;
};

type InstallationOctokit = Awaited<ReturnType<App["getInstallationOctokit"]>>;

async function run() {
  try {
    debug("Start Token Check");
    debug(`Repo info: ${JSON.stringify(context.repo)}`);

    const inputs = getInputs();
    maskSensitiveInputs(inputs);

    const app = new App({
      appId: inputs.appId,
      privateKey: inputs.privateKey,
      oauth: { clientId: inputs.clientId, clientSecret: inputs.clientSecret },
    });

    info("Resolving installation id");
    const installationId = await resolveInstallationId(app, inputs.installationId);
    info(`Resolved installation id ${installationId}`);
    const installationOctokit = await app.getInstallationOctokit(installationId);
    info("Requesting installation access token");
    const installationToken = await requestInstallationToken(
      installationOctokit,
      installationId
    );
    info("Installation access token acquired");

    const publicKeyResp = await getPublicKey(installationOctokit);
    info("Repository public key fetched");

    await updateSecret(
      "APP_ACCESS_TOKEN",
      publicKeyResp,
      installationToken.token,
      installationOctokit
    );
    info("APP_ACCESS_TOKEN secret updated");

    const shouldExposeTokens = inputs.exposeTokens || context.actor === "nektos/act";

    info("Ensuring user tokens are valid");
    const userTokens = await ensureUserTokens({
      app,
      installationOctokit,
      publicKeyResp,
      token: inputs.token,
      userRefreshToken: inputs.userRefreshToken,
    });
    info("User token handling completed");

    if (shouldExposeTokens) {
      setOutput("appToken", installationToken.token);
      if (userTokens?.userAccessToken) {
        setOutput("userToken", userTokens.userAccessToken);
      }
    }

    info("GitHub App credentials refreshed successfully.");
  } catch (runError) {
    error(runError as Error);
    setFailed(runError instanceof Error ? runError.message : String(runError));
  }
}

function getInputs(): Inputs {
  const token = getInput("token");
  const userRefreshToken = getInput("userRefreshToken");
  const privateKey = getInput("privateKey", { required: true });
  const clientId = getInput("clientId", { required: true });
  const clientSecret = getInput("clientSecret", { required: true });
  const appId = getInput("appId", { required: true });
  const installationIdInput = getInput("installationId");
  const exposeTokens = getBooleanInput("exposeTokens");

  let installationId: number | undefined;
  if (installationIdInput) {
    installationId = Number.parseInt(installationIdInput, 10);
    if (Number.isNaN(installationId)) {
      throw new Error("installationId must be a number");
    }
  }

  return {
    token,
    userRefreshToken,
    privateKey,
    clientId,
    clientSecret,
    appId,
    installationId,
    exposeTokens,
  };
}

function maskSensitiveInputs(inputs: Inputs) {
  [
    inputs.token,
    inputs.userRefreshToken,
    inputs.privateKey,
    inputs.clientSecret,
  ]
    .filter((value): value is string => Boolean(value))
    .forEach((value) => setSecret(value));
}

async function resolveInstallationId(app: App, installationId?: number) {
  if (installationId) {
    debug(`Using provided installation id ${installationId}`);
    return installationId;
  }

  const response = await app.octokit.request(
    "GET /repos/{owner}/{repo}/installation",
    {
      ...context.repo,
      headers: {
        "X-GitHub-Api-Version": "2022-11-28",
      },
    }
  );

  debug(
    `Resolved installation id ${response.data.id} for ${context.repo.owner}/${context.repo.repo}`
  );
  return response.data.id;
}

async function requestInstallationToken(
  octo: InstallationOctokit,
  installationId: number
) {
  const response = await octo.request(
    "POST /app/installations/{installation_id}/access_tokens",
    {
      installation_id: installationId,
      headers: {
        "X-GitHub-Api-Version": "2022-11-28",
      },
    }
  );

  debug(
    `Generated installation token expiring at ${response.data.expires_at}`
  );
  setSecret(response.data.token);
  return response.data;
}

async function getPublicKey(octo: InstallationOctokit) {
  const publicKeyResp = await octo.request(
    "GET /repos/{owner}/{repo}/actions/secrets/public-key",
    {
      ...context.repo,
      headers: {
        "X-GitHub-Api-Version": "2022-11-28",
      },
    }
  );

  debug(
    `Fetched repository public key ${publicKeyResp.data.key_id} for ${context.repo.owner}/${context.repo.repo}`
  );
  return publicKeyResp;
}

type UserTokenResult = {
  userAccessToken?: string;
  userRefreshToken?: string;
};

async function ensureUserTokens(params: {
  app: App;
  installationOctokit: InstallationOctokit;
  publicKeyResp: any;
  token: string;
  userRefreshToken: string;
}): Promise<UserTokenResult | undefined> {
  const { app, installationOctokit, publicKeyResp, token, userRefreshToken } =
    params;

  if (!token && !userRefreshToken) {
    debug("No user token inputs provided; skipping user token rotation.");
    return undefined;
  }

  if (token) {
    try {
      info("Checking existing user token validity");
      const checkToken = await app.oauth.checkToken({ token });
      await updateSecret(
        "USER_ACCESS_TOKEN",
        publicKeyResp,
        checkToken.data.token,
        installationOctokit
      );
      info("User access token is still valid");
      return { userAccessToken: checkToken.data.token };
    } catch (checkError) {
      debug(`Provided user token is invalid: ${formatError(checkError)}`);
    }
  }

  if (!userRefreshToken) {
    throw new Error(
      "userRefreshToken input is required when the provided token is invalid."
    );
  }

  info("Refreshing user OAuth token using provided refresh token");
  const refreshed = await app.oauth.refreshToken({
    refreshToken: userRefreshToken,
  });

  setSecret(refreshed.data.access_token);
  setSecret(refreshed.data.refresh_token);

  await updateSecret(
    "USER_ACCESS_TOKEN",
    publicKeyResp,
    refreshed.data.access_token,
    installationOctokit
  );

  await updateSecret(
    "USER_REFRESH_TOKEN",
    publicKeyResp,
    refreshed.data.refresh_token,
    installationOctokit
  );

  info("User OAuth tokens refreshed and secrets updated");
  return {
    userAccessToken: refreshed.data.access_token,
    userRefreshToken: refreshed.data.refresh_token,
  };
}

async function updateSecret(
  secretName: string,
  publicKeyResp: any,
  valueToStore: string,
  octo: InstallationOctokit
) {
  if (!secretName || !publicKeyResp || !valueToStore || !octo) {
    throw new Error("Missing parameters for updateSecret");
  }

  await _sodium.ready;
  const sodium = _sodium;
  const binkey = sodium.from_base64(
    publicKeyResp.data.key,
    sodium.base64_variants.ORIGINAL
  );
  const binsec = sodium.from_string(valueToStore);
  const encBytesAccessToken = sodium.crypto_box_seal(binsec, binkey);
  const completedSecret = sodium.to_base64(
    encBytesAccessToken,
    sodium.base64_variants.ORIGINAL
  );

  debug(`Updating secret ${secretName}`);

  await octo.request("PUT /repos/{owner}/{repo}/actions/secrets/{secret_name}", {
    ...context.repo,
    secret_name: secretName,
    encrypted_value: completedSecret,
    key_id: publicKeyResp.data.key_id,
    headers: {
      "X-GitHub-Api-Version": "2022-11-28",
    },
  });

  debug(`Secret ${secretName} updated.`);
}

function formatError(err: unknown) {
  if (err instanceof Error) {
    return err.message;
  }

  try {
    return JSON.stringify(err);
  } catch (jsonError) {
    error(jsonError as Error);
    return String(err);
  }
}

run();
