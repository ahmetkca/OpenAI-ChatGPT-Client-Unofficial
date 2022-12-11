import * as https from 'node:https';
import { AuthLoginBegins, GetCsrfToken, GetAuthUrl, AuthorizeByAuthUrl, PreLoginIdentifier, LoginIdentifierByEmail, PreLoginPassword, LoginPassword, AuthorizeResume, AuthCallback, GetAPIAuthSessionToken } from '../authFlowRequests/concreteAuthSteps'
const randomUseragent = require('random-useragent');

import { Pipeline } from '../utils/pipeline';

import { Conversation, ConversationPipeline } from './conversation';
import { IAuthLoginBeginsInput, IGetAPIAuthSessionTokenOutput ,IAuthSessionJsonResponse } from '../authFlowRequests/concreteAuthSteps';
import { IAuthCredentials, readAuthCredentialsFromFile, writeAuthCredentialsToFile } from '../utils/utils';


export class ChatGPT {
    private _isLoggedIn: boolean = false;
    public get isLoggedIn(): boolean {
        return this._isLoggedIn;
    }
    private readonly httpAgent: https.Agent;
    private readonly userAgent: string;

    private cookies?: string[] = [];
    private authSessionJson?: IAuthSessionJsonResponse;
    private conversationPipeline: ConversationPipeline;

    constructor() {
        this.httpAgent = new https.Agent({
            keepAlive: true,
            maxSockets: 1,
            maxFreeSockets: 1,
          });
      
          this.userAgent = randomUseragent.getRandom(function (ua: any) {
              return ['Firefox', 'Chrome', 'Safari', 'Opera', 'Edge'].includes(ua.browserName);
          }); // gets a random user agent string

          this.conversationPipeline = new ConversationPipeline();
    }

    isAuthSessionExpired(): boolean {
        if (!this.authSessionJson) {
            return true;
        }

        return this.authSessionJson.expires < new Date();
    }

    isAuthSessionValid(): boolean {
        return !!this.authSessionJson && !this.isAuthSessionExpired() && !!this.cookies;
    }

    checkCachedAuthSessionData(): boolean {
        const authdata = readAuthCredentialsFromFile();
        if (authdata) {
            this.authSessionJson = authdata.authSession;
            this.cookies = authdata.cookies;
            return true;
        }
        return false;
    }

    async login({ email, password }: { email: string, password: string }): Promise<void> {
        if (this.checkCachedAuthSessionData())
        {
            console.log('Using cached auth session data');
            this._isLoggedIn = true;
            return;
        }
        if (this.isAuthSessionValid()) {
            return;
        }

        const pipeline = new Pipeline<IAuthLoginBeginsInput, 
                                        IGetAPIAuthSessionTokenOutput>();
        pipeline.addStep(new AuthLoginBegins({ httpAgent: this.httpAgent, userAgent: this.userAgent }));
        pipeline.addStep(new GetCsrfToken({ httpAgent: this.httpAgent, userAgent: this.userAgent }));
        pipeline.addStep(new GetAuthUrl({ httpAgent: this.httpAgent, userAgent: this.userAgent }));
        pipeline.addStep(new AuthorizeByAuthUrl({ httpAgent: this.httpAgent, userAgent: this.userAgent }));
        pipeline.addStep(new PreLoginIdentifier({ httpAgent: this.httpAgent, userAgent: this.userAgent }));
        pipeline.addStep(new LoginIdentifierByEmail({ httpAgent: this.httpAgent, email, userAgent: this.userAgent }));
        pipeline.addStep(new PreLoginPassword({ httpAgent: this.httpAgent, email, userAgent: this.userAgent }));
        pipeline.addStep(new LoginPassword({ httpAgent: this.httpAgent, email, password, userAgent: this.userAgent }));
        pipeline.addStep(new AuthorizeResume({ httpAgent: this.httpAgent, userAgent: this.userAgent }));
        pipeline.addStep(new AuthCallback({ httpAgent: this.httpAgent, userAgent: this.userAgent }));
        pipeline.addStep(new GetAPIAuthSessionToken({ httpAgent: this.httpAgent, userAgent: this.userAgent }));

        await pipeline.run();

        if (!pipeline.getIsSuccessfull() || !pipeline.getLastStepOutput()) {
            throw new Error('Login failed');
        }

        this.cookies = pipeline.getLastStepOutput().cookies;
        this.authSessionJson = pipeline.getLastStepOutput().authSessionJsonData;
        writeAuthCredentialsToFile({
            cookies: this.cookies,
            authSession: this.authSessionJson
        });
        this._isLoggedIn = true;
    }

    getLoggedInUser(): {id:string,name:string,email:string,image:string,picture:string,groups:any[],features:any[]} | undefined {
        if (!this.authSessionJson) {
            return undefined;
        }
        return this.authSessionJson.user;
    }

    refreshthread(): void { 
        this.conversationPipeline.resetConversation();
    }

    async sendMessage({
        input,
    }: { 
        input: string
     }): Promise<string | undefined> {
        if (!this.authSessionJson || !this.cookies) {
            throw new Error('Not logged in');
        }
        const conversation = new Conversation({
            httpAgent: this.httpAgent,
            userAgent: this.userAgent,
            cookies: this.cookies,
            authSession: this.authSessionJson
        });
        conversation.setMessage(input);
        this.conversationPipeline.addStep(conversation);
        await this.conversationPipeline.run();
        return conversation.getOutput()?.responseMessageFromChatGPT;
    }
}
