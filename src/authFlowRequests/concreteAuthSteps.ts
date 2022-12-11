import { authStepHeaders, authStepReqOpts } from "./authStepRequestInfo";
import * as https from "node:https";
import { OutgoingHttpHeaders } from "node:http";
import { PipelineStep } from "../utils/pipeline";
import { fetch } from "../utils/fetch";
import { IncomingMessage } from "node:http";
import { encodeFormData, includesString } from "../utils/utils";

interface IAuthFlowStepConstructorParams<I> {
    httpAgent: https.Agent;
    userAgent: string;
    authStepId: string;
    input?: I;
}


abstract class AuthFlowStep<I, O> extends PipelineStep<I, O> {
    protected _isSuccessfull: boolean = false;
    get isSuccessfull(): boolean {
        return this._isSuccessfull;
    }

    protected readonly httpAgent: https.Agent;

    /**
     * The ID of the auth step.
     * This is used to look up the request options and headers for the step.
     */
    static readonly authStepId: string;
    protected readonly reqOpts: https.RequestOptions;
    protected readonly reqHeaders: OutgoingHttpHeaders;

    constructor({ 
        httpAgent,
        userAgent,
        authStepId,
        input,
    }: IAuthFlowStepConstructorParams<I>) {
        super(input);
        this.httpAgent = httpAgent;

        if (!authStepId) {
            throw new Error('Auth step ID not set');
        }

        if (!authStepReqOpts.has(authStepId)) {
            throw new Error(`No request options found for auth step ID ${authStepId}`);
        }
        if (!authStepHeaders.has(authStepId)) {
            throw new Error(`No request headers found for auth step ID ${authStepId}`);
        }
        this.reqOpts = authStepReqOpts.get(authStepId) as https.RequestOptions;
        this.reqHeaders = authStepHeaders.get(authStepId) as OutgoingHttpHeaders;
        if (!this.reqOpts || !this.reqHeaders) {
            throw new Error(`Invalid auth step ID: ${authStepId}`);
        }
        this.reqHeaders['User-Agent'] = userAgent;
        this.reqOpts.headers = this.reqHeaders;
        this.reqOpts.agent = this.httpAgent;
    }

    protected async fetch({
        options,
        payload,
        encoding = 'utf-8',
    }: {
        options?: https.RequestOptions;
        payload?: string;
        encoding?: BufferEncoding;
    } = { encoding: 'utf-8' }): Promise<[IncomingMessage, string]> {
        if (!options) {
            console.debug(`No options provided for fetch, using default options for auth step ${this.constructor.name}`);
            options = this.reqOpts;
        }

        console.debug(`fetching ${options.method} ${options.hostname}${options.path}${options.port ? `:${options.port}` : ''}`);

        return fetch({
            options: { ...options },
            payload,
            encoding
        });
    }

    protected combineCookies(cookies: readonly string[], nextCookies: readonly string[]): readonly string[] {
        if (!nextCookies || nextCookies.length === 0) {
            return cookies;
        }
        if (!cookies || cookies.length === 0) {
            return nextCookies;
        }
        return cookies.concat(nextCookies);
    }
}

export type IAuthLoginBeginsInput = void;

export class AuthLoginBegins extends AuthFlowStep<IAuthLoginBeginsInput, { cookies?: string[] }> {
    static override readonly authStepId = 'authLoginBegins';

    constructor({
        httpAgent,
        userAgent,
        input,
    }: Omit<IAuthFlowStepConstructorParams<IAuthLoginBeginsInput>, 'authStepId'>) {
        super({
            httpAgent, userAgent, authStepId: AuthLoginBegins.authStepId, input
        });
    }


    async process(): Promise<{ cookies?: string[] }> {
        const [res, data] = await this.fetch();

        if (res.statusCode !== 200) {
            console.warn(`Auth login begins failed with status code ${res.statusCode}`);
            console.debug(`Response headers: ${JSON.stringify(res.headers)}`);
            console.debug(`Response cookies: ${JSON.stringify(res.headers['set-cookie'])}`);
            console.debug(`Data: ${data}`);
            throw new Error(`Unexpected status code ${res.statusCode} for ${AuthLoginBegins.authStepId}`);
        }

        if (!res.headers['set-cookie']) {
            console.warn(`No cookies found for ${AuthLoginBegins.authStepId}`);
        }

        const nextCookies = this.combineCookies([], res.headers['set-cookie'] ?? []);

        this.output = {
            cookies: [...nextCookies],
        };
        return this.output;
    }
}

export class GetCsrfToken extends AuthFlowStep<{
    cookies: readonly string[]
}, {
    csrfToken: string,
    cookies?: string[]
}> {

    static override readonly authStepId = 'getCsrfToken';

    constructor({
        httpAgent,
        userAgent,
        input,
    }: Omit<IAuthFlowStepConstructorParams<{ cookies: readonly string[] }>, 'authStepId'>) {
        super({
            httpAgent, userAgent,
            authStepId: GetCsrfToken.authStepId, input
        });
    }

    async process(): Promise<{ csrfToken: string, cookies?: string[] }> {
        if (!this.input) {
            throw new Error('No input');
        }
        if (this.input.cookies.length === 0) {
            console.warn(`No cookies provided by previous step for ${GetCsrfToken.authStepId}`);
        }
        this.reqHeaders['Cookie'] = [...this.input.cookies];

        const [res, data] = await this.fetch();

        console.debug(`Status code for ${GetCsrfToken.authStepId}: ${res.statusCode}`);
        console.debug(`Status message for ${GetCsrfToken.authStepId}: ${res.statusMessage}`);

        if (res.statusCode !== 200) {
            throw new Error(`Unexpected status code ${res.statusCode}`);
        }

        if (!res.headers['set-cookie']) {
            throw new Error('No cookies returned');
        }

        const nextCookies = this.combineCookies(this.input.cookies, res.headers['set-cookie']);

        this.output = {
            csrfToken: JSON.parse(data).csrfToken,
            cookies: [...nextCookies],
        };
        return this.output;
    }
}


export class GetAuthUrl extends AuthFlowStep<{
    csrfToken: string,
    cookies: readonly string[]
}, {
    authUrl: URL,
    cookies?: string[]
}> {
    static override readonly authStepId = 'getAuthUrl';

    constructor({
        httpAgent,
        userAgent,
        input,
    } : Omit<IAuthFlowStepConstructorParams<{ csrfToken: string, cookies: readonly string[] }>, 'authStepId'>) {
        super({
            httpAgent, userAgent, 
            authStepId: GetAuthUrl.authStepId, input });
    }

    async process(): Promise<{ authUrl: URL, cookies?: string[] }> {
        if (!this.input) {
            throw new Error('No input');
        }
        if (this.input.cookies.length === 0) {
            console.warn(`No cookies provided by previous step for ${GetAuthUrl.authStepId}`);
        }
        this.reqHeaders['Cookie'] = [...this.input.cookies];

        const formData: Map<string, string> = new Map();
        formData.set("callbackUrl", "/");
        formData.set("csrfToken", this.input.csrfToken);
        formData.set("json", "true");

        const payload = encodeFormData(formData);
        this.reqHeaders['Content-Type'] = 'application/x-www-form-urlencoded';
        this.reqHeaders['Content-Length'] = payload.length;

        const [res, data] = await this.fetch({
            payload,
        });

        if (res.statusCode !== 200) {
            console.warn(`Unexpected status code ${res.statusCode} for ${GetAuthUrl.authStepId}`);
            throw new Error(GetAuthUrl.authStepId + ' failed');
        }

        if (!res.headers['set-cookie']) {
            throw new Error('No cookies returned for ' + GetAuthUrl.authStepId);
        }

        const nextCookies = this.combineCookies(this.input.cookies, res.headers['set-cookie']);

        this.output = {
            authUrl: new URL(JSON.parse(data).url),
            cookies: [...nextCookies],
        };
        return this.output;
    }
}

export class AuthorizeByAuthUrl extends AuthFlowStep<{
    authUrl: URL,
    cookies: readonly string[]
}, {
    redirectUrl: URL,
    cookies?: string[]
}> {
    static override readonly authStepId = 'authorizeByAuthUrl';

    constructor({
        httpAgent,
        userAgent,
        input,
    }: Omit<IAuthFlowStepConstructorParams<{ authUrl: URL, cookies: readonly string[] }>, 'authStepId'>) {
        super({
            httpAgent, userAgent,
            authStepId: AuthorizeByAuthUrl.authStepId, input
        });
    }

    async process(): Promise<{ redirectUrl: URL; cookies?: string[] | undefined; }> {
        if (!this.input) {
            throw new Error('No input');
        }
        if (this.input.cookies.length === 0) {
            console.warn(`No cookies provided by previous step for ${AuthorizeByAuthUrl.authStepId}`);
        }

        // Setup the request options 
        this.reqOpts.hostname = this.input.authUrl.hostname;
        this.reqOpts.path = this.input.authUrl.pathname + this.input.authUrl.search;
        this.reqOpts.method = 'GET';

        this.reqHeaders['Cookie'] = [...this.input.cookies];
        this.reqOpts.headers = this.reqHeaders;

        const [res, data] = await this.fetch();

        if (res.statusCode !== 302 &&
            res.statusMessage !== 'Found'
        ) {
            console.error(data);
            console.error(`Location: ${res.headers.location}`);
            console.error(`Status message: ${res.statusMessage}`);
            console.error(`Unexpected status code ${res.statusCode} for ${AuthorizeByAuthUrl.authStepId}`);
            throw new Error(AuthorizeByAuthUrl.authStepId + ' failed');
        }

        if (res.headers.location === undefined ||
            !res.headers.location.startsWith("/u/login/identifier?state=")
           ) 
        {
            console.error(data);
            console.error(`Location: ${res.headers.location}`);
            console.error(`Status message: ${res.statusMessage}`);
        }

        if (!res.headers['set-cookie']) {
            console.warn('No cookies returned for ' + AuthorizeByAuthUrl.authStepId);
        }

        const nextCookies = this.combineCookies(this.input.cookies, res.headers['set-cookie'] ?? []);

        this.output = {
            redirectUrl: new URL("https://auth0.openai.com" + res.headers['location']),
            cookies: [...nextCookies],
        };
        return this.output;
    }
}

export class PreLoginIdentifier extends AuthFlowStep<{ 
    redirectUrl: URL, 
    cookies: readonly string[] 
}, { 
    redirectUrl: URL, 
    cookies?: string[] 
}> {
    static override readonly authStepId = 'preLoginIdentifier';

    constructor({
        httpAgent,
        userAgent,
        input,
    } : Omit<IAuthFlowStepConstructorParams<{ redirectUrl: URL, cookies: readonly string[] }>, 'authStepId'>) {
        super({
            httpAgent, userAgent,
            authStepId: PreLoginIdentifier.authStepId, input
        })
    }

    async process(): Promise<{ redirectUrl: URL; cookies?: string[] | undefined; }> {
        if (!this.input) {
            throw new Error('No input');
        }
        if (this.input.cookies.length === 0) {
            console.warn(`No cookies provided by previous step for ${PreLoginIdentifier.authStepId}`);
        }

        // Setup the request options
        this.reqOpts.hostname = this.input.redirectUrl.hostname;
        this.reqOpts.path = this.input.redirectUrl.pathname + this.input.redirectUrl.search;
        this.reqOpts.method = 'GET';

        this.reqHeaders['Cookie'] = [...this.input.cookies];

        const [res, data] = await this.fetch();

        if (res.statusCode && res.statusCode >= 400) {
            console.debug(data);
            console.error(`Unexpected status code ${res.statusCode} for ${PreLoginIdentifier.authStepId}`);
            throw new Error(PreLoginIdentifier.authStepId + ' failed');
        }

        if (!res.headers['set-cookie']) {
            console.warn('No cookies returned for ' + PreLoginIdentifier.authStepId);
        }

        const nextCookies = this.combineCookies(this.input.cookies, res.headers['set-cookie'] ?? []);

        this.output = {
            redirectUrl: this.input.redirectUrl,
            cookies: [...nextCookies],
        };
        return this.output;
    }
}

export class LoginIdentifierByEmail extends AuthFlowStep<{
    redirectUrl: URL,
    cookies: readonly string[]
}, {
    refererUrl: URL,
    redirectUrl: URL,
    cookies?: string[]
}> {
    static override readonly authStepId = 'loginIdentifierByEmail';
    private readonly email?: string;

    constructor({
        httpAgent,
        userAgent,
        email,
        input,
    }: Omit<IAuthFlowStepConstructorParams<{ redirectUrl: URL, cookies: readonly string[] }>, 'authStepId'> & { email?: string }) {
        super({
            httpAgent, userAgent,
            authStepId: LoginIdentifierByEmail.authStepId, input
        });
        this.email = email;
    }

    async process(): Promise<{ refererUrl: URL; redirectUrl: URL; cookies?: string[] }> {
        if (!this.email || this.email.length === 0) {
            throw new Error('No email provided');
        }
        if (!this.input) {
            throw new Error('No input');
        }
        if (this.input.cookies.length === 0) {
            console.warn(`No cookies provided by previous step for ${LoginIdentifierByEmail.authStepId}`);
        }

        const formData: Map<string, string> = new Map();
        formData.set("state", this.input.redirectUrl.searchParams.get("state")!);
        formData.set("username", this.email);
        formData.set("js-available", "true");
        formData.set("webauthn-available", "true");
        formData.set("is-brave", "false");
        formData.set("webauthn-platform-available", "true");
        formData.set("action", "default");
        const payload = encodeFormData(formData);

        // Setup the request options
        this.reqOpts.hostname = this.input.redirectUrl.hostname;
        this.reqOpts.path = this.input.redirectUrl.pathname + this.input.redirectUrl.search;
        this.reqOpts.method = 'POST';

        this.reqHeaders['Cookie'] = [...this.input.cookies];
        this.reqHeaders['Content-Type'] = 'application/x-www-form-urlencoded';
        this.reqHeaders['Content-Length'] = payload.length;

        const [res, data] = await this.fetch({
            payload,
        });

        console.debug(`Location from response headers: ${res.headers.location}`);
        console.debug(`statusCode: ${res.statusCode}`);
        console.debug(`statusMessage: ${res.statusMessage}`);

        if (res.statusCode !== 302 &&
            res.statusMessage !== 'Found' &&
            res.headers.location === undefined
        ) {
            console.error(data);
            console.error(`Unexpected status code ${res.statusCode} for ${LoginIdentifierByEmail.authStepId}`);
            throw new Error(LoginIdentifierByEmail.authStepId + ' failed');
        }

        if (!res.headers['set-cookie']) {
            console.warn('No cookies returned for ' + LoginIdentifierByEmail.authStepId);
        }

        const nextCookies = this.combineCookies(this.input.cookies, res.headers['set-cookie'] ?? []);

        this.output = {
            refererUrl: this.input.redirectUrl,
            redirectUrl: new URL("https://" + this.input.redirectUrl.hostname + res.headers.location),
            cookies: [...nextCookies],
        };
        return this.output;
    }
}

export class PreLoginPassword extends AuthFlowStep<{
    refererUrl: URL,
    redirectUrl: URL,
    cookies: readonly string[]
}, {
    redirectUrl: URL,
    cookies?: string[]
}> {
    static override readonly authStepId = 'preLoginPassword';
    private email: string;

    constructor({
        httpAgent,
        userAgent,
        email,
        input,
    }: Omit<IAuthFlowStepConstructorParams<{ refererUrl: URL, redirectUrl: URL, cookies: readonly string[] }>, 'authStepId'> & { email: string }) {
        super({
            httpAgent, userAgent,
            authStepId: PreLoginPassword.authStepId, input
        });
        this.email = email;
    }

    async process(): Promise<{ redirectUrl: URL; cookies?: string[] | undefined; }> {
        if (!this.email || this.email.length === 0) {
            throw new Error('No email provided');
        }

        if (!this.input) {
            throw new Error('No input');
        }
        if (this.input.cookies.length === 0) {
            console.warn(`No cookies provided by previous step for ${PreLoginPassword.authStepId}`);
        }

        // Setup the request headers
        this.reqHeaders['Cookie'] = [...this.input.cookies];
        this.reqHeaders['Referer'] = this.input.refererUrl.href;

        // Setup the request options
        this.reqOpts.hostname = this.input.redirectUrl.hostname;
        this.reqOpts.path = this.input.redirectUrl.pathname + this.input.redirectUrl.search;

        const [res, data] = await this.fetch();

        if (res.statusCode && res.statusCode >= 400) {
            console.error(data);
            console.error(`Unexpected status code ${res.statusCode} for ${PreLoginPassword.authStepId}`);
            throw new Error(PreLoginPassword.authStepId + ' failed');
        }

        if (!res.headers['set-cookie']) {
            console.warn('No cookies returned for ' + PreLoginPassword.authStepId);
        }

        const nextCookies = this.combineCookies(this.input.cookies, res.headers['set-cookie'] ?? []);

        const regex: RegExp = /<span class="ulp-authenticator-selector-text">([a-zA-Z0-9@.-_]+)<\/span>/gm;
        const match = regex.exec(data);
        if (match === null || match.length < 2 || (match[1] && (match[1].length === 0 || match[1] !== this.email))) {
            throw new Error('Email not found in auth page which is unexpected for ' + PreLoginPassword.authStepId);
        }

        this.output = {
            redirectUrl: this.input.redirectUrl,
            cookies: [...nextCookies],
        };
        return this.output;
    }
}

export class LoginPassword extends AuthFlowStep<{
    redirectUrl: URL,
    cookies: readonly string[]
}, {
    refererUrl: URL,
    redirectUrl: URL,
    cookies?: string[]
}> {
    static override readonly authStepId = 'loginPassword';
    private email?: string;
    private password?: string;


    constructor({
        httpAgent,
        userAgent,
        email,
        password,
        input,
    }: Omit<IAuthFlowStepConstructorParams<{redirectUrl: URL, cookies: readonly string[]}>, 'authStepId'> & { email?: string, password?: string }) {
        super({
            httpAgent, userAgent,
            authStepId: LoginPassword.authStepId, input
        });
        this.email = email;
        this.password = password;
    }

    async process(): Promise<{ refererUrl: URL; redirectUrl: URL; cookies?: string[] | undefined; }> {
        if (!this.email || this.email.length === 0 || !this.password || this.password.length === 0) {
            throw new Error('No email or password provided');
        }

        if (!this.input) {
            throw new Error('No input');
        }
        if (this.input.cookies.length === 0) {
            console.warn(`No cookies provided by previous step for ${LoginPassword.authStepId}`);
        }

        const formData: Map<string, string> = new Map();
        formData.set("state", this.input.redirectUrl.searchParams.get("state")!);
        formData.set("username", this.email);
        formData.set("password", this.password);
        formData.set("action", "default");
        const payload = encodeFormData(formData);

        // Setup the request headers
        this.reqHeaders['Cookie'] = [...this.input.cookies];
        this.reqHeaders['Referer'] = this.input.redirectUrl.href;
        this.reqHeaders['Content-Type'] = 'application/x-www-form-urlencoded';
        this.reqHeaders['Content-Length'] = payload.length;

        // Setup the request options
        this.reqOpts.hostname = this.input.redirectUrl.hostname;
        this.reqOpts.path = this.input.redirectUrl.pathname + this.input.redirectUrl.search;

        const [res, data] = await this.fetch({
            payload,
        });

        if (res.statusCode && res.statusCode >= 400) {
            const regex: RegExp = /Wrong email or password/gm;
            const match = regex.exec(data);
            if (match === null) {
                throw new Error("Could not find error message. Probably wrong email or password");
            }
            console.error("Wrong email or password");
            throw new Error("Wrong email or password");
        }

        if (!res.headers['set-cookie']) {
            console.warn('No cookies returned for ' + LoginPassword.authStepId);
        }

        const nextCookies = this.combineCookies(this.input.cookies, res.headers['set-cookie'] ?? []);

        if (!res.headers.location) {
            throw new Error('No redirect location returned for ' + LoginPassword.authStepId);
        }

        this.output = {
            refererUrl: this.input.redirectUrl,
            redirectUrl: new URL("https://" + this.input.redirectUrl.hostname + res.headers.location),
            cookies: [...nextCookies],
        };
        return this.output;
    }
}

export class AuthorizeResume extends AuthFlowStep<{
    refererUrl: URL,
    redirectUrl: URL,
    cookies: readonly string[]
}, {
    redirectUrl: URL,
    cookies?: string[]
}> {
    static override readonly authStepId: string = 'authorizeResume';

    constructor({
        httpAgent,
        userAgent,
        input,
    }: Omit<IAuthFlowStepConstructorParams<{refererUrl: URL, redirectUrl: URL, cookies: readonly string[]}>, 'authStepId'>) {
        super({
            httpAgent, userAgent,
            authStepId: AuthorizeResume.authStepId, input
        });
    }

    async process(): Promise<{ redirectUrl: URL; cookies?: string[] | undefined; }> {
        if (!this.input) {
            throw new Error('No input');
        }
        if (this.input.cookies.length === 0) {
            console.warn(`No cookies provided by previous step for ${AuthorizeResume.authStepId}`);
        }

        // Setup the request headers
        this.reqHeaders['Cookie'] = [...this.input.cookies];
        this.reqHeaders['Referer'] = this.input.refererUrl.href;

        // Setup the request options
        this.reqOpts.hostname = this.input.redirectUrl.hostname;
        this.reqOpts.path = this.input.redirectUrl.pathname + this.input.redirectUrl.search;

        const [res, data] = await this.fetch();

        if (res.statusCode !== 302 && res.statusMessage !== 'Found') {
            console.error(data);
            console.error(`Unexpected status code ${res.statusCode} for ${AuthorizeResume.authStepId}`);
            throw new Error(AuthorizeResume.authStepId + ' failed');
        }

        if (!res.headers['set-cookie']) {
            console.warn('No cookies returned for ' + AuthorizeResume.authStepId);
        }

        const nextCookies = this.combineCookies(this.input.cookies, res.headers['set-cookie'] ?? []);

        if (!res.headers.location) {
            throw new Error('No redirect location returned for ' + AuthorizeResume.authStepId);
        }

        this.output = {
            redirectUrl: new URL(res.headers.location),
            cookies: [...nextCookies],
        };
        return this.output;
    }
}

export class AuthCallback extends AuthFlowStep<{
    redirectUrl: URL,
    cookies: readonly string[],
}, {
    cookies?: string[]
}> {
    static override readonly authStepId = 'authCallback';

    constructor({
        httpAgent,
        userAgent,
        input,
    }: Omit<IAuthFlowStepConstructorParams<{redirectUrl: URL, cookies: readonly string[]}>, 'authStepId'>) {
        super({
            httpAgent, userAgent,
            authStepId: AuthCallback.authStepId, input
        });
    }

    async process(): Promise<{ cookies?: string[] | undefined; }> {
        if (!this.input) {
            throw new Error('No input');
        }

        if (this.input.cookies.length === 0) {
            console.warn(`No cookies provided by previous step for ${AuthCallback.authStepId}`);
        }

        // Setup the request headers
        this.reqHeaders['Cookie'] = [...this.input.cookies];

        // Setup the request options
        this.reqOpts.hostname = this.input.redirectUrl.hostname;
        this.reqOpts.path = this.input.redirectUrl.pathname + this.input.redirectUrl.search;

        const [res, data] = await this.fetch();

        if (res.statusCode !== 302 && res.statusMessage !== 'Found') {
            console.error(data);
            console.error(`Unexpected status code ${res.statusCode} for ${AuthCallback.authStepId}`);
            throw new Error(AuthCallback.authStepId + ' failed');
        }

        if (!res.headers['location']) {
            console.warn('No redirect location returned for ' + AuthCallback.authStepId);
        }

        if (!res.headers['set-cookie']) {
            console.warn('No cookies returned for ' + AuthCallback.authStepId);
        }

        const nextCookies = this.combineCookies(this.input.cookies, res.headers['set-cookie'] ?? []);

        this.output = {
            cookies: [...nextCookies],
        };
        return this.output;
    }
}

export interface IAuthSessionJsonResponse {
    user: {
        id: string;
        name: string;
        email: string;
        image: string;
        picture: string;
        groups: string[];
        features: string[];
    };
    expires: Date;
    accessToken: string;
}

export interface IGetAPIAuthSessionTokenOutput {
    authSessionJsonData: IAuthSessionJsonResponse,
    cookies: string[]
}

export class GetAPIAuthSessionToken extends AuthFlowStep<{
    cookies: readonly string[],
}, IGetAPIAuthSessionTokenOutput> {
    static override readonly authStepId = 'getAPIAuthSessionToken';

    constructor({
        httpAgent,
        userAgent,
        input,
    }: Omit<IAuthFlowStepConstructorParams<{ cookies: readonly string[] }>, 'authStepId'>) {
        super({
            httpAgent, userAgent,
            authStepId: GetAPIAuthSessionToken.authStepId, input
        });
    }

    async process(): Promise<IGetAPIAuthSessionTokenOutput> {
        if (!this.input) {
            throw new Error('No input');
        }
        
        if (this.input.cookies.length === 0) {
            console.warn(`No cookies provided by previous step for ${GetAPIAuthSessionToken.authStepId}`);
        }

        if (!includesString("__Secure-next-auth.session-token", this.input.cookies)) {
            throw new Error("Missing session token");
        }

        // Setup the request headers
        this.reqHeaders['Cookie'] = [...this.input.cookies];

        const [res, data] = await this.fetch();

        if (res.statusCode !== 200 && res.statusMessage !== 'OK') {
            console.error(data);
            console.error(`Unexpected status code ${res.statusCode} for ${GetAPIAuthSessionToken.authStepId}`);
            console.error(`Cookies: ${this.input.cookies}`);
            throw new Error(GetAPIAuthSessionToken.authStepId + ' failed');
        }

        if (!res.headers['set-cookie']) {
            console.error(`The cookies returned at this step is important for the next step. Please report this issue.`);
            console.error(`Cookies: ${this.input.cookies}`);
            throw new Error('No cookies returned for ' + GetAPIAuthSessionToken.authStepId);
        }

        const nextCookies = this.combineCookies(this.input.cookies, res.headers['set-cookie']);

        const authSessionJsonResponse = JSON.parse(data) as IAuthSessionJsonResponse;

        this.output = {
            authSessionJsonData: authSessionJsonResponse,
            cookies: [...nextCookies],
        };
        return this.output;
    }
}


