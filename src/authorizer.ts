// A simple token-based authorizer example to demonstrate how to use an authorization token
// to allow or deny a request. In this example, the caller named 'user' is allowed to invoke
// a request if the client-supplied token value is 'allow'. The caller is not allowed to invoke
// the request if the token value is 'deny'. If the token value is 'unauthorized' or an empty
// string, the authorizer function returns an HTTP 401 status code. For any other token value,
// the authorizer returns an HTTP 500 status code.
// Note that token values are case-sensitive.

import {
    APIGatewayEventDefaultAuthorizerContext,
    CustomAuthorizerCallback,
    APIGatewayAuthorizerResult,
    APIGatewayAuthorizerResultContext,
} from 'aws-lambda';
import { verify, JwtPayload } from 'jsonwebtoken';

interface AuthorizerEvent {
    type: 'TOKEN' | 'REQUEST';
    methodArn: string;
    authorizationToken: string;
}

interface KeycloakJwt extends JwtPayload {
    auth_time: number;
    session_state: string;
    'allowd-origins': string[];
    realm_access: {
        roles: string[];
    };
    resource_access: {
        account: {
            roles: [];
        };
    };
    scope: string;
    sid: string;
    email_verified: boolean;
    preferred_username: string;
}

const publicKey = process.env.PUBLIC_KEY;
if (!publicKey) {
    throw new Error('public key is none!');
}

export const handler = async (
    event: AuthorizerEvent,
    context: APIGatewayEventDefaultAuthorizerContext,
    callback: CustomAuthorizerCallback,
) => {
    console.log('event:', event);
    console.log('context:', context);

    if (event.type != 'TOKEN') {
        const message = `Unsupported type ${event.type}`;
        console.warn(message);
        return callback(null, generatePolicy('user', 'Deny', event.methodArn, { message }));
    }

    // remove bearer prefix
    const token = event.authorizationToken.replace('Bearer ', '');

    verify(token, publicKey, (error, decoded) => {
        console.log('error:', error);
        console.log('decoded:', decoded);

        if (error) {
            console.log('error:', error);
            return callback(null, generatePolicy('user', 'Deny', event.methodArn, { message: error.message }));
        }

        if (typeof decoded === 'string' || !decoded) {
            console.log('invalid decoded:', decoded);
            return callback(null, generatePolicy('user', 'Deny', event.methodArn));
        }

        const token = decoded as KeycloakJwt;
        console.log('token:', token);

        if (token.realm_access.roles.includes('default-roles-myrealm')) {
            return callback(null, generatePolicy('user', 'Allow', event.methodArn));
        }
        console.warn('権限がありません');
        return callback(null, generatePolicy('user', 'Deny', event.methodArn));
    });
};

// Help function to generate an IAM policy
const generatePolicy = (
    principalId: string,
    effect: string,
    resource: string,
    context: APIGatewayAuthorizerResultContext = {},
): APIGatewayAuthorizerResult => {
    if (!effect || !resource) {
        throw new Error();
    }

    const authResponse: APIGatewayAuthorizerResult = {
        principalId,
        policyDocument: {
            Version: '2012-10-17',
            Statement: [
                {
                    Action: 'execute-api:Invoke',
                    Effect: effect,
                    Resource: resource,
                },
            ],
        },
        context,
    };

    // Optional output with custom properties of the String, Number or Boolean type.
    return authResponse;
};
