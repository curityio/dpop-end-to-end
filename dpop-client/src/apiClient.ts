import {Configuration} from './configuration.js';
import {DPopUtility} from './security/dpopUtility.js';

export class ApiClient {

    private readonly configuration: Configuration;

    public constructor(configuration: Configuration) {
        this.configuration = configuration;
    }

    public async getOrders(accessToken: string, dpop: DPopUtility): Promise<any> {

        const dpopProofJwt = await dpop.getProofJwt(this.configuration.apiUrl, 'POST', undefined);

        const response = await fetch(this.configuration.apiUrl, {

            method: 'GET',
            headers: {
                Accept: 'application/json',
                Authorization: `DPoP ${accessToken}`,
                DPoP: dpopProofJwt,

            },
        });

        if (!response.ok) {
            throw new Error(`API returned an error status of ${response.status}`);
        }

        return await response.json();
    }
}