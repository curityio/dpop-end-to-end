import EventEmitter from 'node:events';
import http from 'node:http';
import getPort from 'get-port';
import open from 'open';
import {Configuration} from '../configuration.js';
import {DPopUtility} from './dpopUtility.js';
import {generateHash, generateRandomString, processOAuthPostResponseError} from './utils.js';

/*
 * A code flow client that uses RFC 8252 and DPoP
 */
export class CodeFlowClient {

    private readonly configuration: Configuration;
    private metadata: any;
    private redirectUri: string;
    private codeVerifier: string;
    private readonly eventEmitter;
    private httpServer: http.Server | null;

    public constructor(configuration: Configuration) {

        this.configuration = configuration;
        this.metadata = null;
        this.redirectUri = '';
        this.codeVerifier = '';
        this.eventEmitter = new EventEmitter();
        this.httpServer = null;
    }

    public async frontChannelRequest(dpop: DPopUtility): Promise<string> {

        await this.getMetadata();

        this.codeVerifier = generateRandomString();
        const codeChallenge = generateHash(this.codeVerifier);

        const port = await getPort({port: 3333});
        this.redirectUri = `http://127.0.0.1:${port}/callback`;

        const dpopJkt = await dpop.getDpopJkt();

        let requestUrl = this.metadata.authorization_endpoint;
        requestUrl += `?client_id=${encodeURIComponent(this.configuration.dpopClientId)}`;
        requestUrl += `&redirect_uri=${encodeURIComponent(this.redirectUri)}`;
        requestUrl += '&response_type=code';
        requestUrl += `&scope=${encodeURIComponent(this.configuration.scope)}`;
        requestUrl += `&code_challenge=${codeChallenge}`;
        requestUrl += '&code_challenge_method=S256';
        requestUrl += `&dpop_jkt=${dpopJkt}`;
        requestUrl += '&prompt=login';

        this.httpServer = http.createServer((request: http.IncomingMessage, response: http.ServerResponse) => {

            const requestUrl = new URL(request.url || '', `http://${request.headers.host}`);
            if (requestUrl.pathname !== '/callback') {
                response.end();
                return;
            }

            response.write('Console client login attempt completed - you can close this window');
            response.end();
        
            this.eventEmitter.emit('LOGIN_COMPLETE', requestUrl);
        });

        this.httpServer.listen(port);
        await open(requestUrl);

        return new Promise<string>((resolve, reject) => {

            this.eventEmitter.once('LOGIN_COMPLETE', (responseUrl: string) => {

                this.httpServer?.close();
                this.httpServer = null;
                
                const args = new URLSearchParams(new URL(responseUrl).search);
                const code = args.get('code') || '';
                const errorCode = args.get('error') || '';
                const errorDescription = args.get('error_description') || '';
                
                if (errorCode) {
                    reject(new Error(`Authorization response error: ${errorCode}, ${errorDescription}`));
                } else if (!code) {
                    reject(new Error(`Authorization response error: no authorizaton code`));
                } else {
                    resolve(code);
                }
            });
        });
    }

    public async backChannelRequest(code: string, dpop: DPopUtility): Promise<string> {

        let dpopProofJwt = await dpop.getProofJwt(this.metadata.token_endpoint, 'POST', undefined, undefined);

        const formData = new URLSearchParams();
        formData.append('grant_type', 'authorization_code');
        formData.append('client_id', this.configuration.dpopClientId);
        formData.append('redirect_uri', this.redirectUri!);
        formData.append('code', code);
        formData.append('code_verifier', this.codeVerifier!);

        const options: RequestInit = {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded',
                'DPoP': dpopProofJwt,
            },
            body: formData.toString(),
        };
        
        let response = await fetch(this.metadata.token_endpoint, options);
        if (response.status === 400) {

            const dpopNonce = response.headers.get('dpop-nonce');
            if (dpopNonce) {

                dpopProofJwt = await dpop.getProofJwt(this.metadata.token_endpoint, 'POST', dpopNonce);
                (options.headers as any)['DPoP'] = dpopProofJwt;
                response = await fetch(this.metadata.token_endpoint, options);
            }
        }

        if (!response.ok) {

            const text = await response.text();
            throw new Error(processOAuthPostResponseError('Introspection', response.status, text));
        }

        const tokens = await response.json() as any;
        return tokens.access_token;
    }

    private async getMetadata(): Promise<void> {

        const response = await fetch(`${this.configuration.authorizationServerBaseUrl}/oauth/v2/oauth-anonymous/.well-known/openid-configuration`);
        if (!response.ok) {
            throw new Error(`Metadata response error, status: ${response.status}`);
        }

        this.metadata = await response.json();
    }
}
