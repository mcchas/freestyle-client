import hashJs from 'hash.js';
import { BigInteger } from 'jsbn';
import { Buffer } from 'buffer';
import { CognitoCommonException, CognitoError, CognitoException } from './error.js';

import {
  calculateSignature,
  calculateU,
  decodeJwt,
  generateA,
  generateSmallA,
  getPasswordAuthenticationKey,
  randomBytes,
  calculateSecretHash
} from './utils.js';

export interface UserAttribute {
  Name: string;
  Value: string;
}

/**
 * Cognito related OAuth props.
 */
export interface OAuth2Props {
  /**
   * Cognito domain for OAuth2 token endpoints.
   */
  cognitoDomain: string;

  /**
   * Requested OAuth scopes
   * @example ['email', 'openid']
   */
  scopes: string[];

  /**
   * Redirect URL after a successful OAuth2 authentication.
   */
  redirectUrl: string;

  /**
   * Response type.
   */
  responseType: 'code';
}

export interface CognitoClientProps {
  /**
   * Cognito User Pool ID
   * @example eu-central-1_lv6wixN9f
   */
  userPoolId: string;

  /**
   * Cognito User Pool Client ID
   */
  userPoolClientId: string;

  /**
   * Optional Cognito endpoint. Useful for local testing.
   * If not defined the endpoint will be determined by @see userPoolId .
   */
  endpoint?: string;

  /**
   * Cognito OAuth related options. See @see OAuthProps .
   */
  oAuth2?: OAuth2Props;

  /**
   * Cognito Client Secret
   */
  clientSecret?: string;
}

/**
 * Cognito User Session
 */
export interface Session {
  /**
   * JWT Access Token
   */
  accessToken: string;

  /**
   * JWT ID Token
   */
  idToken: string;

  /**
   * JWT refresh token
   */
  refreshToken: string;

  /**
   * Validity of the session in time stamp as milliseconds.
   */
  expiresIn: number;
}

/**
 * Represents the decoded values from a JWT ID token.
 */
export interface IdToken extends Record<string, string | string[] | number | boolean> {
  'cognito:username': string;
  'cognito:groups': string[];
  email_verified: boolean;
  email: string;
  iss: string;
  origin_jti: string;
  aud: string;
  event_id: string;
  token_use: 'id';
  auth_time: number;
  exp: number;
  iat: number;
  jti: string;
  sub: string;
}

export interface AccessToken extends Record<string, string | string[] | number | boolean> {
  auth_time: number;
  client_id: string;
  event_id: string;
  exp: number;
  iat: number;
  iss: string;
  jti: string;
  origin_jti: string;
  scope: string;
  sub: string;
  token_use: 'access';
  username: string;
}

export interface DecodedTokens {
  idToken: IdToken;
  accessToken: AccessToken;
}

/**
 * List of used and supported Cognito API calls.
 * @see https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_Operations.html for more details
 */
export enum CognitoServiceTarget {
  InitiateAuth = 'InitiateAuth',
  RespondToAuthChallenge = 'RespondToAuthChallenge',
  SignUp = 'SignUp',
  ConfirmSignUp = 'ConfirmSignUp',
  ChangePassword = 'ChangePassword',
  RevokeToken = 'RevokeToken',
  ForgotPassword = 'ForgotPassword',
  ConfirmForgotPassword = 'ConfirmForgotPassword',
  ResendConfirmationCode = 'ResendConfirmationCode',
  UpdateUserAttributes = 'UpdateUserAttributes',
  VerifyUserAttribute = 'VerifyUserAttribute'
}

/**
 * Cognito supported federated identities public providers.
 * @see https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-identity.html for more information.
 */
export enum CognitoIdentityProvider {
  Cognito = 'COGNITO',
  Google = 'Google',
  Facebook = 'Facebook',
  Amazon = 'LoginWithAmazon',
  Apple = 'SignInWithApple'
}

export interface AuthenticationResult {
  AccessToken: string;
  ExpiresIn: number;
  IdToken: string;
  RefreshToken: string;
}

export interface AuthenticationResponse {
  AuthenticationResult: AuthenticationResult;
}

export interface ChallengeResponse {
  ChallengeName: 'PASSWORD_VERIFIER';
  ChallengeParameters: {
    SALT: string;
    SECRET_BLOCK: string;
    SRP_B: string;
    USERNAME: string;
    USER_ID_FOR_SRP: string;
  };
}

export function authResultToSession(authenticationResult: AuthenticationResult): Session {
  return {
    accessToken: authenticationResult.AccessToken,
    idToken: authenticationResult.IdToken,
    expiresIn: new Date().getTime() + authenticationResult.ExpiresIn * 1000,
    refreshToken: authenticationResult.RefreshToken
  };
}

export async function cognitoRequest(body: object, serviceTarget: CognitoServiceTarget, cognitoEndpoint: string) {
  const cognitoResponse = await fetch(cognitoEndpoint, {
    headers: {
      'x-amz-target': `AWSCognitoIdentityProviderService.${serviceTarget}`,
      'content-type': 'application/x-amz-json-1.1'
    },
    method: 'POST',
    body: JSON.stringify(body)
  });

  if (cognitoResponse && cognitoResponse.status < 300) {
    return cognitoResponse.json();
  }

  const cognitoResponseBody = await cognitoResponse.json();

  /**
   * The whole error handling and value sanitization was inspired
   * by @see https://github.com/aws-amplify/amplify-js/blob/1f5eefd9c40285eb99e57764ac8fca1f9519e2c6/packages/core/src/clients/serde/json.ts#L14
   */

  const sanitizeErrorType = (rawValue: string | number): string => {
    const [cleanValue] = rawValue.toString().split(/[,:]+/);
    if (cleanValue.includes('#')) {
      return cleanValue.split('#')[1];
    }
    return cleanValue;
  };

  const errorMessage =
    cognitoResponse.headers.get('X-Amzn-ErrorMessage') ??
    cognitoResponseBody.message ??
    cognitoResponseBody.Message ??
    'Unknown error';

  const cognitoException = sanitizeErrorType(
    cognitoResponse.headers.get('X-Amzn-ErrorType') ??
      cognitoResponseBody.code ??
      cognitoResponseBody.__type ??
      CognitoCommonException.Unknown
  );

  throw new CognitoError(errorMessage, cognitoException as CognitoException);
}

/**
 * Lightweight AWS Cogito client without any AWS SDK dependencies.
 */
export class CognitoClient {
  private readonly cognitoEndpoint: string;
  private readonly cognitoPoolName: string;
  private readonly userPoolClientId: string;
  private readonly clientSecret?: string;


  private readonly oAuth?: OAuth2Props;

  constructor({ userPoolId, userPoolClientId, endpoint, oAuth2: oAuth, clientSecret }: CognitoClientProps) {
    const [cognitoPoolRegion, cognitoPoolName] = userPoolId.split('_');
    this.cognitoEndpoint = (endpoint || `https://cognito-idp.${cognitoPoolRegion}.amazonaws.com`).replace(/\/$/, '');
    this.cognitoPoolName = cognitoPoolName;
    this.userPoolClientId = userPoolClientId;
    this.oAuth = oAuth;
    this.clientSecret = clientSecret;
  }

  static getDecodedTokenFromSession(session: Session): DecodedTokens {
    const { payload: idToken } = decodeJwt<IdToken>(session.idToken);
    const { payload: accessToken } = decodeJwt<AccessToken>(session.accessToken);
    return {
      idToken,
      accessToken
    };
  }

  /**
   *
   * Performs user authentication with username and password through ALLOW_USER_SRP_AUTH .
   * @see https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-authentication-flow.html for more details
   *
   * @param username Username
   * @param password Password
   *
   * @throws {InitiateAuthException}
   */
  async authenticateUserSrp(username: string, password: string): Promise<Session> {
    const smallA = await generateSmallA();
    const A = generateA(smallA);

    const initiateAuthPayload = {
      AuthFlow: 'USER_SRP_AUTH',
      ClientId: this.userPoolClientId,
      AuthParameters: {
        USERNAME: username,
        SRP_A: A.toString(16),
        ...(this.clientSecret) && 
        {
          SECRET_HASH: calculateSecretHash(this.clientSecret, this.userPoolClientId, username)
        },
      },
      ClientMetadata: {}
    };

    const challenge = (await cognitoRequest(
      initiateAuthPayload,
      CognitoServiceTarget.InitiateAuth,
      this.cognitoEndpoint
    )) as ChallengeResponse;

    const B = new BigInteger(challenge.ChallengeParameters.SRP_B, 16);
    const salt = new BigInteger(challenge.ChallengeParameters.SALT, 16);
    const U = calculateU(A, B);

    const hkdf = getPasswordAuthenticationKey(
      this.cognitoPoolName,
      challenge.ChallengeParameters.USER_ID_FOR_SRP,
      password,
      B,
      U,
      smallA,
      salt
    );

    const { signature, timeStamp } = calculateSignature(
      this.cognitoPoolName,
      challenge.ChallengeParameters.USER_ID_FOR_SRP,
      challenge.ChallengeParameters.SECRET_BLOCK,
      hkdf
    );

    const respondToAuthChallengePayload = {
      ChallengeName: 'PASSWORD_VERIFIER',
      ClientId: this.userPoolClientId,
      ChallengeResponses: {
        PASSWORD_CLAIM_SECRET_BLOCK: challenge.ChallengeParameters.SECRET_BLOCK,
        PASSWORD_CLAIM_SIGNATURE: signature,
        USERNAME: challenge.ChallengeParameters.USER_ID_FOR_SRP,
        TIMESTAMP: timeStamp,
        ...(this.clientSecret) && {
          SECRET_HASH: calculateSecretHash(this.clientSecret, this.userPoolClientId, challenge.ChallengeParameters.USER_ID_FOR_SRP)
        },
      },
      ClientMetadata: {}
    };

    const { AuthenticationResult } = await cognitoRequest(
      respondToAuthChallengePayload,
      CognitoServiceTarget.RespondToAuthChallenge,
      this.cognitoEndpoint
    );

    return authResultToSession(AuthenticationResult);
  }

  /**
   *
   * Performs user authentication with username and password through USER_PASSWORD_AUTH .
   * @see https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-authentication-flow.html for more details
   *
   * @param username Username
   * @param password Password
   * @throws {InitiateAuthException}
   */
  async authenticateUser(username: string, password: string): Promise<Session> {
    const initiateAuthPayload = {
      AuthFlow: 'USER_PASSWORD_AUTH',
      ClientId: this.userPoolClientId,
      AuthParameters: {
        USERNAME: username,
        PASSWORD: password
      },
      ClientMetadata: {}
    };

    const { AuthenticationResult } = (await cognitoRequest(
      initiateAuthPayload,
      CognitoServiceTarget.InitiateAuth,
      this.cognitoEndpoint
    )) as AuthenticationResponse;

    const session = authResultToSession(AuthenticationResult);
    return session;
  }

  /**
   * Returns a new session based on the given refresh token.
   *
   * @param refreshToken
   * @returns @see Session
   * @throws {InitiateAuthException}
   */
  public async refreshSession(refreshToken: string): Promise<Session> {
    const refreshTokenPayload = {
      AuthFlow: 'REFRESH_TOKEN_AUTH',
      ClientId: this.userPoolClientId,
      AuthParameters: {
        REFRESH_TOKEN: refreshToken,
        ...(this.clientSecret) && 
        {
          SECRET_HASH: this.clientSecret
        },
      },
      ClientMetadata: {}
    };

    const { AuthenticationResult } = (await cognitoRequest(
      refreshTokenPayload,
      CognitoServiceTarget.InitiateAuth,
      this.cognitoEndpoint
    )) as AuthenticationResponse;

    if (!AuthenticationResult.RefreshToken) {
      AuthenticationResult.RefreshToken = refreshToken;
    }

    return authResultToSession(AuthenticationResult);
  }

  /**
   *
   * @param username Username
   * @param password Password
   *
   * @throws {SignUpException}
   */
  async signUp(username: string, password: string, userAttributes?: UserAttribute[]) {
    const signUpPayload = {
      ClientId: this.userPoolClientId,
      Username: username,
      Password: password,
      UserAttributes: userAttributes
    };

    const data = await cognitoRequest(signUpPayload, CognitoServiceTarget.SignUp, this.cognitoEndpoint);

    return {
      id: data.UserSub as string,
      confirmed: data.UserConfirmed as boolean
    };
  }

  /**
   * Confirms the user registration via verification code.
   *
   * @param username Username
   * @param code Confirmation code the user gets through the registration E-Mail
   *
   * @throws {ConfirmSignUpException}
   */
  async confirmSignUp(username: string, code: string) {
    const confirmSignUpPayload = {
      ClientId: this.userPoolClientId,
      ConfirmationCode: code,
      Username: username
    };

    await cognitoRequest(confirmSignUpPayload, CognitoServiceTarget.ConfirmSignUp, this.cognitoEndpoint);
  }

  /**
   *
   * @param currentPassword Current user password.
   * @param newPassword  New user password.
   *
   * @throws {ChangePasswordException}
   */
  async changePassword(currentPassword: string, newPassword: string, accessToken: string) {
    const changePasswordPayload = {
      PreviousPassword: currentPassword,
      ProposedPassword: newPassword,
      AccessToken: accessToken
    };

    await cognitoRequest(changePasswordPayload, CognitoServiceTarget.ChangePassword, this.cognitoEndpoint);
  }

  /**
   * Updates the user attributes.
   *
   * @param userAttributes List of user attributes to update.
   * @param accessToken Access token of the current user.
   *
   * @throws {UpdateUserAttributesException}
   */
  async updateUserAttributes(userAttributes: UserAttribute[], accessToken: string) {
    const updateUserAttributesPayload = {
      UserAttributes: userAttributes,
      AccessToken: accessToken
    };

    await cognitoRequest(updateUserAttributesPayload, CognitoServiceTarget.UpdateUserAttributes, this.cognitoEndpoint);
  }

  /**
   * Verifies a given user attribute
   *
   * @param attributeName Name of the attribute to verify
   * @param code  Verification code
   * @param accessToken Access token of the current user.
   *
   * @throws {VerifyUserAttributeException}
   */
  async verifyUserAttribute(attributeName: string, code: string, accessToken: string) {
    const verifyUserAttributePayload = {
      AttributeName: attributeName,
      Code: code,
      AccessToken: accessToken
    };

    await cognitoRequest(verifyUserAttributePayload, CognitoServiceTarget.VerifyUserAttribute, this.cognitoEndpoint);
  }

  /**
   * Sign out the user and remove the current user session.
   *
   * @throws {RevokeTokenException}
   */
  async signOut(refreshToken: string) {
    const revokeTokenPayload = {
      Token: refreshToken,
      ClientId: this.userPoolClientId
    };

    await cognitoRequest(revokeTokenPayload, CognitoServiceTarget.RevokeToken, this.cognitoEndpoint);
  }

  /**
   * Request forgot password.
   * @param username Username
   *
   * @throws {ForgotPasswordException}
   */
  async forgotPassword(username: string) {
    const forgotPasswordPayload = {
      ClientId: this.userPoolClientId,
      Username: username
    };

    await cognitoRequest(forgotPasswordPayload, CognitoServiceTarget.ForgotPassword, this.cognitoEndpoint);
  }

  /**
   * Confirms the new password via the given code send via cognito triggered by @see forgotPassword .
   *
   * @param username Username
   * @param newPassword New password
   * @param confirmationCode Confirmation code which the user got through E-mail
   *
   * @throws {ConfirmForgotPasswordException}
   */
  async confirmForgotPassword(username: string, newPassword: string, confirmationCode: string) {
    const confirmForgotPasswordPayload = {
      ClientId: this.userPoolClientId,
      Username: username,
      ConfirmationCode: confirmationCode,
      Password: newPassword
    };

    await cognitoRequest(
      confirmForgotPasswordPayload,
      CognitoServiceTarget.ConfirmForgotPassword,
      this.cognitoEndpoint
    );
  }

  /**
   * Triggers cognito to resend the confirmation code
   * @param username Username
   *
   * @throws {ResendConfirmationCodeException}
   */
  async resendConfirmationCode(username: string) {
    const resendConfirmationCodePayLoad = {
      ClientId: this.userPoolClientId,
      Username: username
    };

    await cognitoRequest(
      resendConfirmationCodePayLoad,
      CognitoServiceTarget.ResendConfirmationCode,
      this.cognitoEndpoint
    );
  }

  /**
   * Returns a link to Cognito`s Hosted UI for OAuth2 authentication.
   * This method works in conjunction with @see handleCodeFlow .
   *
   * @param identityProvider When provided, this will generate a link which
   * tells Cognito`s Hosted UI to redirect to the given federated identity provider.
   *
   * @throws {Error}
   */
  async generateOAuthSignInUrl(identityProvider?: CognitoIdentityProvider) {
    if (this.oAuth === undefined) {
      throw Error('You have to define oAuth options to use generateFederatedSignUrl');
    }

    const state = (await randomBytes(32)).toString('hex');
    const pkce = (await randomBytes(128)).toString('hex');

    const code_challenge = Buffer.from(hashJs.sha256().update(pkce).digest())
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');

    const queryParams = new URLSearchParams();

    queryParams.append('redirect_uri', this.oAuth.redirectUrl);
    queryParams.append('response_type', this.oAuth.responseType);
    queryParams.append('client_id', this.userPoolClientId);
    identityProvider && queryParams.append('identity_provider', identityProvider);
    queryParams.append('scope', this.oAuth.scopes.join(' '));
    queryParams.append('state', state);
    queryParams.append('code_challenge', code_challenge);
    queryParams.append('code_challenge_method', 'S256');

    return {
      url: `${this.oAuth.cognitoDomain}/oauth2/authorize?${queryParams.toString()}`,
      state,
      pkce
    };
  }

  /**
   *
   * Handles Cognito`s OAuth2 code flow after redirection from Cognito`s Hosted UI.
   * The method call assumes that @see generateOAuthSignInUrl was used to
   * generated the link to the Hosted UI.
   *
   * @param returnUrl The full return URL from redirection after a successful OAuth2
   * authentication.
   *
   * @throws {Error}
   */
  async handleCodeFlow(returnUrl: string, pkce: string): Promise<Session> {
    if (this.oAuth === undefined) {
      throw Error('You have to define oAuth options to use handleCodeFlow');
    }

    const url = new URL(returnUrl);
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');

    if (code === null || state === null) {
      throw Error('code or state parameter is missing from return url.');
    }

    const urlParams = new URLSearchParams();

    urlParams.append('grant_type', 'authorization_code');
    urlParams.append('code', code);
    urlParams.append('client_id', this.userPoolClientId);
    urlParams.append('redirect_uri', this.oAuth.redirectUrl);
    urlParams.append('code_verifier', pkce);

    const tokenEndpoint = `${this.oAuth.cognitoDomain}/oauth2/token`;

    const response = await fetch(tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: urlParams.toString()
    });

    const { access_token, refresh_token, id_token, expires_in, error } = await response.json();

    if (error) {
      throw new Error(error);
    }

    const session = authResultToSession({
      AccessToken: access_token,
      RefreshToken: refresh_token,
      IdToken: id_token,
      ExpiresIn: expires_in
    });

    return session;
  }
}
