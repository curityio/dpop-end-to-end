import {Configuration} from '../configuration.js';
import {DPopUtility} from './dpopUtility.js';
import {processOAuthResponseError } from './utils.js';

/*
 * An API client for the Curity Identity Server
 */
export class UserInfoClient {

    private readonly configuration: Configuration;

    public constructor(configuration: Configuration) {
        this.configuration = configuration;
    }

    public async execute(opaqueAccessToken: string, dpop: DPopUtility): Promise<any> {

        const url = `${this.configuration.authorizationServerBaseUrl}/oauth/v2/oauth-userinfo`;
        let dpopProofJwt = await dpop.getProofJwt(url, 'GET', dpop.authorizationServerNonce, opaqueAccessToken);
    
        const options: RequestInit = {
            method: 'GET',
            headers: {
                'Accept': 'application/jwt',
                'Authorization': `DPoP ${opaqueAccessToken}`,
                'DPoP': dpopProofJwt,
            },
        };
        
        let response = await fetch(url, options);
        if (response.status === 401) {

            const dpopNonce = response.headers.get('dpop-nonce');
            if (dpopNonce) {

                dpop.authorizationServerNonce = dpopNonce;
                dpopProofJwt = await dpop.getProofJwt(url, 'GET', dpop.authorizationServerNonce, opaqueAccessToken);
                (options.headers as any)['DPoP'] = dpopProofJwt;
                response = await fetch(url, options);
            }
        }

        if (!response.ok) {

            const text = await response.text();
            throw new Error(processOAuthResponseError('Userinfo', response.status, text));
        }

        return await response.json();
    }
}
