import {
  debug,
  error,
  getInput,
  info,
  setFailed,
  setOutput,
  setSecret,
} from "@actions/core";
import { context } from "@actions/github";
import { App } from "@octokit/app";
import _sodium from "libsodium-wrappers";

const GITHUB_API_VERSION = "2026-03-10";
const GITHUB_API_VERSION_HEADER = {
  accept: "application/vnd.github+json",
  "X-GitHub-Api-Version": GITHUB_API_VERSION,
};

type Mode = "app-token" | "rotate-secrets";
type PermissionLevel = "read" | "write";
type InstallationTokenPermissions = Record<string, PermissionLevel>;

type Inputs = {
  mode: Mode;
  token: string;
  userRefreshToken: string;
  privateKey: string;
  clientId: string;
  clientSecret: string;
  appId: string;
  installationId?: number;
  permissions: InstallationTokenPermissions;
};

type InstallationOctokit = Awaited<ReturnType<App["getInstallationOctokit"]>>;

async function run() {
  try {
    debug("Start Token Check");
    debug(`Repo info: ${JSON.stringify(context.repo)}`);

    const inputs = getInputs();
    maskSensitiveInputs(inputs);

    const app = createApp(inputs);

    info("Resolving installation id");
    const installationId = await resolveInstallationId(app, inputs.installationId);
    info(`Resolved installation id ${installationId}`);
    info("Requesting installation access token");
    const installationToken = await requestInstallationToken(
      app,
      installationId,
      inputs.permissions
    );
    info("Installation access token acquired");

    if (inputs.mode === "app-token") {
      setOutput("token", installationToken.token);
      info("Fresh installation token exposed as a step output.");
      return;
    }

    const installationOctokit = await app.getInstallationOctokit(installationId);
    const publicKeyResp = await getPublicKey(installationOctokit);
    info("Repository public key fetched");

    await updateSecret(
      "APP_ACCESS_TOKEN",
      publicKeyResp,
      installationToken.token,
      installationOctokit
    );
    info("APP_ACCESS_TOKEN secret updated");

    info("Ensuring user tokens are valid");
    await ensureUserTokens({
      app,
      installationOctokit,
      publicKeyResp,
      token: inputs.token,
      userRefreshToken: inputs.userRefreshToken,
    });
    info("User token handling completed");

    info("Repository token secrets refreshed successfully.");
  } catch (runError) {
    error(runError as Error);
    setFailed(runError instanceof Error ? runError.message : String(runError));
  }
}

function getInputs(): Inputs {
  const mode = getMode();
  const token = getInput("token");
  const userRefreshToken = getInput("userRefreshToken");
  const privateKey = getInput("privateKey", { required: true });
  const clientId = getInput("clientId");
  const clientSecret = getInput("clientSecret");
  const appId = getInput("appId", { required: true });
  const installationIdInput = getInput("installationId");
  const permissions = mode === "app-token" ? getPermissions() : {};

  if ((clientId && !clientSecret) || (!clientId && clientSecret)) {
    throw new Error("clientId and clientSecret must be provided together.");
  }

  if ((token || userRefreshToken) && (!clientId || !clientSecret)) {
    throw new Error(
      "clientId and clientSecret are required when rotating user OAuth tokens."
    );
  }

  let installationId: number | undefined;
  if (installationIdInput) {
    installationId = Number.parseInt(installationIdInput, 10);
    if (Number.isNaN(installationId)) {
      throw new Error("installationId must be a number");
    }
  }

  return {
    mode,
    token,
    userRefreshToken,
    privateKey,
    clientId,
    clientSecret,
    appId,
    installationId,
    permissions,
  };
}

function getMode(): Mode {
  const mode = getInput("mode") || "app-token";
  if (mode === "app-token" || mode === "rotate-secrets") {
    return mode;
  }

  throw new Error("mode must be either app-token or rotate-secrets");
}

function getPermissions(): InstallationTokenPermissions {
  const permissions: InstallationTokenPermissions = {};
  addPermission(permissions, "contents", "permission-contents");
  addPermission(permissions, "pull_requests", "permission-pull-requests");
  return permissions;
}

function addPermission(
  permissions: InstallationTokenPermissions,
  permissionName: string,
  inputName: string
) {
  const value = getInput(inputName);
  if (!value) {
    return;
  }

  if (value !== "read" && value !== "write") {
    throw new Error(`${inputName} must be either read or write.`);
  }

  permissions[permissionName] = value;
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

function createApp(inputs: Inputs) {
  if (inputs.clientId && inputs.clientSecret) {
    return new App({
      appId: inputs.appId,
      privateKey: inputs.privateKey,
      oauth: { clientId: inputs.clientId, clientSecret: inputs.clientSecret },
    });
  }

  return new App({
    appId: inputs.appId,
    privateKey: inputs.privateKey,
  });
}

async function resolveInstallationId(app: App, installationId?: number) {
  if (installationId) {
    debug(`Using provided installation id ${installationId}`);
    return installationId;
  }

  let response;
  try {
    response = await app.octokit.request(
      "GET /repos/{owner}/{repo}/installation",
      {
        ...context.repo,
        headers: GITHUB_API_VERSION_HEADER,
      }
    );
  } catch (err) {
    if (isHttpStatus(err, 404)) {
      throw new Error(
        `GitHub App installation was not found for ${context.repo.owner}/${context.repo.repo}. ` +
          "Install the app on this repository, grant it access to this repository, or pass a valid installationId for an installation that can access it."
      );
    }

    throw err;
  }

  debug(
    `Resolved installation id ${response.data.id} for ${context.repo.owner}/${context.repo.repo}`
  );
  return response.data.id;
}

async function requestInstallationToken(
  app: App,
  installationId: number,
  permissions: InstallationTokenPermissions
) {
  const response = await app.octokit.request(
    "POST /app/installations/{installation_id}/access_tokens",
    {
      installation_id: installationId,
      ...(Object.keys(permissions).length ? { permissions } : {}),
      headers: GITHUB_API_VERSION_HEADER,
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
      headers: GITHUB_API_VERSION_HEADER,
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
    headers: GITHUB_API_VERSION_HEADER,
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

function isHttpStatus(err: unknown, status: number) {
  return (
    typeof err === "object" &&
    err !== null &&
    "status" in err &&
    (err as { status?: unknown }).status === status
  );
}

run();
