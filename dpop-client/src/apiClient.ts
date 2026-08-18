import {Configuration} from './configuration.js';

export class ApiClient {

    private readonly configuration: Configuration;

    public constructor(configuration: Configuration) {
        this.configuration = configuration;
    }

    public async getOrders(accessToken: string): Promise<any> {

        const response = await fetch(this.configuration.apiUrl, {

            method: 'GET',
            headers: {
                accept: 'application/json',
                authorization: `Bearer ${accessToken}`,
            },
        });

        if (!response.ok) {
            throw new Error(`API returned an error status of ${response.status}`);
        }

        return await response.json();
    }
}