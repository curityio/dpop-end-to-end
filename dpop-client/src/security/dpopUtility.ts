import {calculateThumbprint, generateKeyPair, generateProof, KeyPair} from 'dpop';

/*
 * A wrapper to supply limited DPoP operations to other application code
 */
export class DPopUtility {

    private keypair: KeyPair | null = null;
    public authorizationServerNonce: string | undefined;
    public resourceServerNonce: string | undefined;

    public async initialize(): Promise<void> {
        this.keypair = await generateKeyPair('ES256', {extractable: false});
    }

    public async getDpopJkt(): Promise<string> {
        return await calculateThumbprint(this.keypair!.publicKey)
    }

    public async getProofJwt(url: string, method: string, nonce: string | undefined, accessToken: string | undefined) {
        return await generateProof(this.keypair!, url, method, nonce, accessToken);
    }
}
