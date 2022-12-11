import { IAuthSessionJsonResponse } from "../authFlowRequests/concreteAuthSteps";
import fs from 'node:fs';
import crypto from 'node:crypto';


const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const randomMilliseconds = (min: number, max: number) => Math.floor(Math.random() * (max - min + 1) + min);

const randomNumberBetween = (min: number, max: number): number => {
    return Math.floor(Math.random() * (max - min + 1) + min);
}

const encodeFormData = (formData: Map<string, string>): string => {
    let urlencodedString = "";
    for (const [key, value] of formData) {
        urlencodedString += `${encodeURIComponent(key)}=${encodeURIComponent(value)}&`;
    }
    urlencodedString = urlencodedString.slice(0, urlencodedString.length - 1);
    return urlencodedString;
}

const includesString = (str: string, substrings:  readonly string[]): boolean => {
    for (const substring of substrings) {
        if (substring.includes(str)) {
            return true;
        }
    }
    return false;
}

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
        console.error(e);
        return undefined;
    }
};


export { delay, randomMilliseconds, randomNumberBetween, encodeFormData, includesString };
