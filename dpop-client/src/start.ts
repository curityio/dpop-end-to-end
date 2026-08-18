import fs from 'fs';
import {decodeJwt} from 'jose'
import {ApiClient} from './apiClient.js';
import {Configuration} from './configuration.js';
import {CodeFlowClient} from './security/codeFlowClient.js';
import {IntrospectClient} from './security/introspectClient.js';
import { DPopUtility } from './security/dpopUtility.js';

const configurationJson = fs.readFileSync('config.json', 'utf8');
const configuration = JSON.parse(configurationJson) as Configuration;

try {

    //
    // First, prepare DPoP
    //
    const dpop = new DPopUtility();
    await dpop.initialize();

    //
    // First run a code flow and get an access token
    //
    console.log('Logging in and getting an access token ...')
    const codeFlowClient = new CodeFlowClient(configuration);
    const code = await codeFlowClient.frontChannelRequest(dpop);
    const opaqueAccessToken = await codeFlowClient.backChannelRequest(code, dpop);
    console.log(`Received opaque access token: ${opaqueAccessToken}`);

    //
    // Next act as an API gateway to visualize the access token
    //
    console.log('Visualizing sender-constrained access token ...');
    const introspectClient = new IntrospectClient(configuration);
    const jwtAccessToken = await introspectClient.execute(opaqueAccessToken);
    const claims = decodeJwt(jwtAccessToken);
    console.log(JSON.stringify(claims, null, 2));

    //
    // Call the API with the opaque access token and also a DPoP proof
    //
    console.log('Calling API to get orders ...');
    const apiClient = new ApiClient(configuration);
    const orders = await apiClient.getOrders(opaqueAccessToken, dpop);
    console.log(JSON.stringify(orders, null, 2));

} catch (e: any) {

    console.log(e.message);
}
