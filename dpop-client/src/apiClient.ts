import {Configuration} from './configuration.js';
import {DPopUtility} from './security/dpopUtility.js';

/*
 * An API client for a customer API
 */
export class ApiClient {

    private readonly configuration: Configuration;
    private nonce: string | undefined;

    public constructor(configuration: Configuration) {
        this.configuration = configuration;
        this.nonce = undefined;
    }

    public async getOrders(accessToken: string, dpop: DPopUtility): Promise<any> {

        let dpopProofJwt = await dpop.getProofJwt(this.configuration.apiUrl, 'GET', this.nonce, accessToken);

        const options: RequestInit = {
            method: 'GET',
            headers: {
                'Accept': 'application/json',
                Authorization: `DPoP ${accessToken}`,
                'DPoP': dpopProofJwt,
            },
        };

        let response = await fetch(this.configuration.apiUrl, options);
        if (response.status === 401) {

            const dpopNonce = response.headers.get('dpop-nonce');
            if (dpopNonce) {

                this.nonce = dpopNonce;
                dpopProofJwt = await dpop.getProofJwt(this.configuration.apiUrl, 'GET', this.nonce, accessToken);
                (options.headers as any)['DPoP'] = dpopProofJwt;
                response = await fetch(this.configuration.apiUrl, options);
            }
        }

        if (!response.ok) {
            throw new Error(`API returned an error status of ${response.status}`);
        }

        return await response.json();
    }
}
