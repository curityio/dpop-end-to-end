import {Configuration} from '../configuration.js';
import {processOAuthResponseError} from './utils.js';

/*
 * A utility to visualize access tokens for learning purposes
 */
export class IntrospectClient {

    private readonly configuration: Configuration;

    public constructor(configuration: Configuration) {
        this.configuration = configuration;
    }

    public async execute(opaqueAccessToken: string): Promise<string> {
    
        const formData = new URLSearchParams();
        formData.append('client_id', this.configuration.introspectClientId);
        formData.append('client_secret', this.configuration.introspectClientSecret);
        formData.append('token', opaqueAccessToken);

        const options: RequestInit = {
            method: 'POST',
            headers: {
                'Accept': 'application/jwt',
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: formData.toString(),
        };

        const url = `${this.configuration.authorizationServerBaseUrl}/oauth/v2/oauth-introspect`;
        const response = await fetch(url, options);
        if (!response.ok) {

            const text = await response.text();
            throw new Error(processOAuthResponseError('Introspection', response.status, text));
        }

        return await response.text();
    }
}
