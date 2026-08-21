import express from 'express';
import fs from 'fs';
import {JWTPayload } from 'jose';
import {Configuration} from './configuration.js';
import {OAuthFilter} from './oauthFilter.js';
import {getOrders} from './ordersRepository.js';

const configurationJson = fs.readFileSync('config.json', 'utf8');
const configuration = JSON.parse(configurationJson) as Configuration;

const app = express();
app.set('etag', false);

const oauthFilter = new OAuthFilter(configuration);
app.use('/', oauthFilter.validateAccessToken);

app.get('/', (request: express.Request, response: express.Response) => {

    const claims: JWTPayload = response.locals.claims;
    const authorizedOrders = getOrders(claims['customer_id'] as string);

    response.setHeader('content-type', 'application/json');
    response.status(200).send(JSON.stringify(authorizedOrders, null, 2));

    console.log(`Example API returned a success result at ${new Date().toISOString()}`);
});

app.listen(configuration.port, () => {
    console.log(`Example API is listening on HTTP port ${configuration.port}`);
});
