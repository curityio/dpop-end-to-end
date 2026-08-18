import crypto from 'node:crypto'

export function base64UrlEncode(data: string): string {
    return data
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
}

export function base64UrlDecode(input: string): Buffer {

    const base64 = input
        .replace(/-/g, '+')
        .replace(/_/g, '/');

    return Buffer.from(base64, 'base64');
}

export function generateRandomString(): string {
    return base64UrlEncode(crypto.randomBytes(32).toString('base64'));
}

export function generateHash(data: string): string {
    
    const hash = crypto.createHash('sha256');
    hash.update(data);
    return base64UrlEncode(hash.digest('base64'));
}

/*
 * Collect OAuth error details
 */
export function processOAuthPostResponseError(operation: string, status: number, text: any): string {

    let errorData: any = null;
    if (text) {
        try {
            errorData = JSON.parse(text);
        } catch {
        }
    }
    
    let message = `${operation} failed`;
    if (status) {
        message += `, status: ${status}`;
    }
    if (errorData?.error) {
        message += `, code: ${errorData.error}`;
    }
    if (errorData?.error_description) {
        message += `, description: ${errorData.error_description}`;
    }
    
    throw new Error(message);
}