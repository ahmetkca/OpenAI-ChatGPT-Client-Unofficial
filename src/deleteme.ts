import crypto from 'crypto';
import fs from 'fs';
import { IAuthSessionJsonResponse } from './authFlowRequests/concreteAuthSteps';

const ALGORITHM = process.env['CRYPTO_ALGORITHM'] || undefined;
const SECRET_KEY = process.env['CRYPTO_SECRET_KEY'] || undefined;

const encrypt = ({ data }: { data: string }) => {
    if (!ALGORITHM || !SECRET_KEY) {
        throw new Error("No algorithm or secret key provided.");
    }
    const iv = crypto.randomBytes(16)

    const cipher = crypto.createCipheriv(ALGORITHM, SECRET_KEY, iv)

    const encrypted = Buffer.concat([cipher.update(data), cipher.final()])

    return {
        iv: iv.toString('hex'),
        content: encrypted.toString('hex')
    }
}

const decrypt = ({ hash }: { hash: { iv: string, content: string } }) => {
    if (!ALGORITHM || !SECRET_KEY) {
        throw new Error("No algorithm or secret key provided.");
    }
    const decipher = crypto.createDecipheriv(ALGORITHM, SECRET_KEY, Buffer.from(hash.iv, 'hex'))

    const decrpyted = Buffer.concat([decipher.update(Buffer.from(hash.content, 'hex')), decipher.final()])

    return decrpyted.toString()
}


export interface IAuthCredentials {
    cookies: string[];
    authSession: IAuthSessionJsonResponse;
}

export const writeAuthCredentialsToFile = ({
    cookies,
    authSession,
}: IAuthCredentials): void => {
    const authCredentialsString = JSON.stringify({ cookies, authSession });
    fs.writeFileSync('authCredentials_copy.json', JSON.stringify(encrypt({ data: authCredentialsString })));
};

type Optional<T> = T | undefined;

export const readAuthCredentialsFromFile = (): Optional<IAuthCredentials> => {
    try {
        const encryptedAuthCredentialsJsonString = fs.readFileSync('authCredentials_copy.json', 'utf-8');
        const authCredentials = JSON.parse(decrypt({ hash: JSON.parse(encryptedAuthCredentialsJsonString) }));
        return authCredentials;
    } catch(e) {
        return undefined;
    }
};

const authSession = readAuthCredentialsFromFile();

if (authSession) {
    console.log(authSession);
    writeAuthCredentialsToFile(authSession);
}