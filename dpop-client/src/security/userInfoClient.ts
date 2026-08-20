import {Configuration} from '../configuration.js';
import {DPopUtility} from './dpopUtility.js';
import {processOAuthPostResponseError } from './utils.js';

/*
 * An API client for the Curity Identity Server
 */
export class UserInfoClient {

    private readonly configuration: Configuration;

    public constructor(configuration: Configuration) {
        this.configuration = configuration;
    }

    public async execute(opaqueAccessToken: string, dpop: DPopUtility): Promise<any> {

        let dpopProofJwt = await dpop.getProofJwt(this.configuration.apiUrl, 'GET', undefined, opaqueAccessToken);
    
        const options: RequestInit = {
            method: 'GET',
            headers: {
                'Accept': 'application/jwt',
                'Authorization': `DPoP ${opaqueAccessToken}`,
                'DPoP': dpopProofJwt,
            },
        };

        const url = `${this.configuration.authorizationServerBaseUrl}/oauth/v2/oauth-userinfo`;
        let response = await fetch(url, options);
        if (response.status === 400 || response.status === 401) {

            const dpopNonce = response.headers.get('dpop-nonce');
            if (dpopNonce) {

                dpopProofJwt = await dpop.getProofJwt(url, 'GET', dpopNonce, opaqueAccessToken);
                (options.headers as any)['DPoP'] = dpopProofJwt;
                response = await fetch(url, options);
            }
        }

        if (!response.ok) {

            const text = await response.text();
            throw new Error(processOAuthPostResponseError('Userinfo', response.status, text));
        }

        return await response.json();
    }
}
