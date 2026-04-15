import {PreTokenGenerationV2TriggerHandler} from "aws-lambda";

// Standard Cognito user pool attributes to enrich the access token with.
// These are not included in Cognito access tokens by default.
const STANDARD_ATTRIBUTES_TO_ENRICH = [
    "email",
    "email_verified",
    "name",
    "given_name",
    "family_name",
    "middle_name",
    "nickname",
    "preferred_username",
    "phone_number",
    "phone_number_verified",
    "address",
    "birthdate",
    "zoneinfo",
    "locale",
    "updated_at",
] as const;

// Standard JWT claims already present in Cognito access tokens.
// These must not be overridden.
const RESERVED_CLAIMS = new Set([
    "sub",
    "iss",
    "aud",
    "exp",
    "iat",
    "auth_time",
    "jti",
    "token_use",
    "username",
    "cognito:username",
    "origin_jti",
    "event_id",
    "scope",
    "version",
]);

export const handler: PreTokenGenerationV2TriggerHandler = async event => {
    console.log("Event:", JSON.stringify(event));

    const {userAttributes} = event.request;

    const claimsToAddOrOverride: Record<string, string> = {};

    for (const attr of STANDARD_ATTRIBUTES_TO_ENRICH) {
        if (!RESERVED_CLAIMS.has(attr) && userAttributes[attr] !== undefined) {
            claimsToAddOrOverride[attr] = userAttributes[attr];
        }
    }

    for (const [key, value] of Object.entries(userAttributes)) {
        if (key.startsWith("custom:") && !RESERVED_CLAIMS.has(key)) {
            claimsToAddOrOverride[key] = value;
        }
    }

    event.response.claimsAndScopeOverrideDetails = {
        accessTokenGeneration: {
            claimsToAddOrOverride,
        },
    };

    console.log("Result:", JSON.stringify(event));
    return event;
};
