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
const requiredRole = process.env.REQUIRED_ROLE;

if (!publicKey || !requiredRole) {
    throw new Error('Environment variables are missing.');
}

export const handler = async (
    event: AuthorizerEvent,
    context: APIGatewayEventDefaultAuthorizerContext,
    callback: CustomAuthorizerCallback,
) => {
    console.log('Event:', event);
    console.log('Context:', context);

    if (event.type != 'TOKEN') {
        const message = `Unsupported type ${event.type}`;
        console.warn(message);
        return callback(null, generatePolicy('user', 'Deny', event.methodArn, { message }));
    }

    // remove bearer prefix
    const token = event.authorizationToken.replace('Bearer ', '');

    verify(token, publicKey, (error, decoded) => {
        if (error) {
            console.warn('Error:', error);
            return callback(null, generatePolicy('user', 'Deny', event.methodArn, { message: error.message }));
        }

        if (typeof decoded === 'string' || !decoded) {
            console.warn('Invalid decoded:', decoded);
            return callback(null, generatePolicy('user', 'Deny', event.methodArn));
        }
        const keycloakToken = decoded as KeycloakJwt;
        console.log('KeycloakToken:', keycloakToken);

        // check with roles
        if (keycloakToken.realm_access.roles.includes(requiredRole)) {
            return callback(null, generatePolicy('user', 'Allow', event.methodArn));
        }

        console.warn('Not authorized.');
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

    console.log('Response: ', JSON.stringify(authResponse, null, '\t'));
    return authResponse;
};
