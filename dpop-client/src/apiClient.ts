import {Configuration} from './configuration.js';
import {DPopUtility} from './security/dpopUtility.js';

export class ApiClient {

    private readonly configuration: Configuration;

    public constructor(configuration: Configuration) {
        this.configuration = configuration;
    }

    public async getOrders(accessToken: string, dpop: DPopUtility): Promise<any> {

        let dpopProofJwt = await dpop.getProofJwt(this.configuration.apiUrl, 'GET', undefined);

        const options: RequestInit = {
            method: 'GET',
            headers: {
                'Accept': 'application/json',
                Authorization: `DPoP ${accessToken}`,
                'DPoP': dpopProofJwt,
            },
        };

        let response = await fetch(this.configuration.apiUrl, options);
        if (response.status === 400) {

            const dpopNonce = response.headers.get('dpop-nonce');
            if (dpopNonce) {

                dpopProofJwt = await dpop.getProofJwt(this.configuration.apiUrl, 'GET', dpopNonce);
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